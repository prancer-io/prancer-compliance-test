package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

# https://docs.microsoft.com/en-us/azure/templates/Microsoft.Cache/redis

# PR-AZR-CLD-ARC-001

default enableSslPort = null
# default is false
azure_attribute_absence ["enableSslPort"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    not has_property(resource.properties, "enableNonSslPort")
}

azure_issue ["enableSslPort"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    resource.properties.enableNonSslPort == true
}

enableSslPort {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    not azure_attribute_absence["enableSslPort"]
    not azure_issue["enableSslPort"]
}

enableSslPort {
	lower(input.resources[_].type) == "microsoft.cache/redis"
    azure_attribute_absence["enableSslPort"]
    not azure_issue["enableSslPort"]
}

enableSslPort = false {
    azure_issue["enableSslPort"]
}

enableSslPort_err = "Redis cache is currently allowing unsecure connection via a non ssl port opened" {
    azure_issue["enableSslPort"]
}

enableSslPort_metadata := {
    "Policy Code": "PR-AZR-CLD-ARC-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure that the Redis Cache accepts only SSL connections",
    "Policy Description": "It is recommended that Redis Cache should allow only SSL connections. Note: some Redis tools (like redis-cli) do not support SSL. When using such tools plain connection ports should be enabled.",
    "Resource Type": "Microsoft.Cache/redis",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/Microsoft.Cache/redis"
}


# https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis/linkedservers

# PR-AZR-CLD-ARC-002

default serverRole = null

azure_attribute_absence["serverRole"] {
    count([c | lower(input.resources[_].type) == "microsoft.cache/redis/linkedservers"; c := 1]) == 0
}

# azure_attribute_absence["serverRole"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.cache/redis/linkedservers"
#     not resource.dependsOn
# }

azure_attribute_absence ["serverRole"] {
   resource := input.resources[_]
   lower(resource.type) == "microsoft.cache/redis/linkedservers"
   not resource.properties.serverRole
}

azure_issue["serverRole"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.cache/redis/linkedservers";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.properties.serverRole) == "secondary";
              c := 1]) == 0
}

# azure_issue ["serverRole"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.cache/redis/linkedservers"
#     lower(resource.properties.serverRole) != "secondary"
# }

serverRole {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    not azure_attribute_absence["serverRole"]
    not azure_issue["serverRole"]
}

serverRole = false {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    azure_attribute_absence["serverRole"]
}

serverRole = false {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    azure_issue["serverRole"]
}

serverRole_err = "Azure Redis Cache linked backup server currently does not have secondary role." {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    azure_issue["serverRole"]
} else = "Azure Redis Cache linked server property 'serverRole' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    azure_attribute_absence["serverRole"]
}

serverRole_metadata := {
    "Policy Code": "PR-AZR-CLD-ARC-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Redis cache should have a backup",
    "Policy Description": "Replicate Redis Cache server data to another Redis Cache server using geo replication. This feature is only available for Premium tier Redis Cache. From performance point of view, Microsoft recommends that both Redis Caches (Primary and the linked secondary) reside in the same region.",
    "Resource Type": "Microsoft.Cache/redis/linkedservers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis/linkedservers"
}



# PR-AZR-CLD-ARC-003

default redis_public_access = null

azure_attribute_absence["redis_public_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    not resource.properties.publicNetworkAccess
}

azure_issue["redis_public_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    lower(resource.properties.publicNetworkAccess) != "disabled"
}

redis_public_access {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    not azure_attribute_absence["redis_public_access"]
    not azure_issue["redis_public_access"]
}

redis_public_access = false {
    azure_attribute_absence["redis_public_access"]
}

redis_public_access = false {
    azure_issue["redis_public_access"]
}

redis_public_access_err = "Azure Redis Cache with public access detected!" {
    azure_issue["redis_public_access"]
} else = "Azure Cache for Redis attribute publicNetworkAccess missing in the resource" {
    azure_attribute_absence["redis_public_access"]
}

redis_public_access_metadata := {
    "Policy Code": "PR-AZR-CLD-ARC-003",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Cache for Redis should disable public network access",
    "Policy Description": "Disabling public network access improves security by ensuring that the Azure Cache for Redis isn't exposed on the public internet. You can limit exposure of your Azure Cache for Redis by creating private endpoints instead. Learn more at: https://docs.microsoft.com/azure/azure-cache-for-redis/cache-private-link.",
    "Resource Type": "microsoft.cache/redis",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis"
}


# PR-AZR-CLD-ARC-004
#

default arc_subnet_id = null

azure_attribute_absence["arc_subnet_id"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    not resource.properties.subnetId
}

azure_issue["arc_subnet_id"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    count(resource.properties.subnetId) == 0
}

arc_subnet_id {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    not azure_issue["arc_subnet_id"]
    not azure_attribute_absence["arc_subnet_id"]
}

arc_subnet_id = false {
    azure_issue["arc_subnet_id"]
}

arc_subnet_id = false {
    azure_attribute_absence["arc_subnet_id"]
}

arc_subnet_id_err = "Azure Cache for Redis is not reside within a virtual network" {
    azure_issue["arc_subnet_id"]
} else = "Azure Cache for Redis attribute subnetId missing in the resource" {
    azure_attribute_absence["arc_subnet_id"]
}

arc_subnet_id_metadata := {
    "Policy Code": "PR-AZR-CLD-ARC-004",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Cache for Redis should reside within a virtual network",
    "Policy Description": "Azure Virtual Network deployment provides enhanced security and isolation for your Azure Cache for Redis, as well as subnets, access control policies, and other features to further restrict access.When an Azure Cache for Redis instance is configured with a virtual network, it is not publicly addressable and can only be accessed from virtual machines and applications within the virtual network.",
    "Resource Type": "microsoft.cache/redis",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis"
}

#
# PR-AZR-CLD-ARC-005

default arc_private_endpoint = null

azure_attribute_absence["arc_private_endpoint"] {
    count([c | lower(input.resources[_].type) == "microsoft.network/privateendpoints"; c := 1]) == 0
}

azure_issue ["arc_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.network/privateendpoints";
              contains(lower(r.properties.privateLinkServiceConnections[_].properties.privateLinkServiceId), lower(concat("/", [resource.type, resource.name])));
              c := 1]) == 0
}

arc_private_endpoint {
	lower(input.resources[_].type) == "microsoft.cache/redis"
    not azure_attribute_absence["arc_private_endpoint"]
    not azure_issue["arc_private_endpoint"]
}

arc_private_endpoint = false {
	lower(input.resources[_].type) == "microsoft.cache/redis"
    azure_issue["arc_private_endpoint"]
}

arc_private_endpoint = false {
	lower(input.resources[_].type) == "microsoft.cache/redis"
    azure_attribute_absence["arc_private_endpoint"]
}

arc_private_endpoint_err = "Azure Storage Account does not configure with private endpoints" {
	lower(input.resources[_].type) == "microsoft.cache/redis"
    azure_issue["arc_private_endpoint"]
} else = "Azure Private endpoints resoruce is missing" {
	lower(input.resources[_].type) == "microsoft.cache/redis"
    azure_attribute_absence["arc_private_endpoint"]
}

arc_private_endpoint_metadata := {
    "Policy Code": "PR-AZR-CLD-ARC-005",
    "Type": "Cloud",  
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Cache for redis should use private link",
    "Policy Description": "Azure Private Link lets you connect your virtual network to Azure services without a public IP address at the source or destination. The Private Link platform handles the connectivity between the consumer and services over the Azure backbone network. By mapping private endpoints to your cache for redis, data leakage risks are reduced. Learn more about private links at - https://aka.ms/azureprivatelinkoverview",
    "Resource Type": "microsoft.cache/redis",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis"
}

#
# PR-AZR-CLD-ARC-006

default redis_persistence_enabled  = null

azure_attribute_absence["redis_persistence_enabled "] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    not resource.properties.redisConfiguration.rdb-backup-enabled
}


azure_issue["redis_persistence_enabled "] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    lower(resource.properties.redisConfiguration.rdb-backup-enabled) != "true"
}

redis_persistence_enabled {
	resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    not azure_attribute_absence["redis_persistence_enabled "]
    not azure_issue["redis_persistence_enabled "]
}


redis_persistence_enabled = false {
    azure_issue["redis_persistence_enabled "]
}

redis_persistence_enabled = false {
    azure_attribute_absence["redis_persistence_enabled "]
}

redis_persistence_enabled_err = "Azure Redis Cache Persistence is currently not enabled." {
    azure_issue["redis_persistence_enabled "]
} else = "Microsoft.Cache/redis property 'redisConfiguration.rdb-backup-enabled' need to be exist. Currently its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["redis_persistence_enabled "]
}

redis_persistence_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-ARC-006",
    "Type": "Cloud",  
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Persistence is enabled on Redis Cache to Perform complete system backups",
    "Policy Description": "Enable Redis persistence. Redis persistence allows you to persist data stored in Redis. You can also take snapshots and back up the data, which you can load in case of a hardware failure. This is a huge advantage over Basic or Standard tier where all the data is stored in memory and there can be potential data loss in case of a failure where Cache nodes are down.",
    "Resource Type": "microsoft.cache/redis",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis"
}


#
# PR-AZR-CLD-ARC-007

default min_tls_version_redis = null

azure_attribute_absence["min_tls_version_redis"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    not resource.properties.minimumTlsVersion
}

azure_issue["min_tls_version_redis"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    to_number(resource.properties.minimumTlsVersion) != 1.2
}

min_tls_version_redis {
	resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    not azure_attribute_absence["min_tls_version_redis"]
    not azure_issue["min_tls_version_redis"]
}


min_tls_version_redis = false {
    azure_issue["min_tls_version_redis"]
}

min_tls_version_redis = false {
    azure_attribute_absence["min_tls_version_redis"]
}

min_tls_version_redis_err = "Azure Redis Cache currently doesn't have latest version of tls configured" {
    azure_issue["min_tls_version_redis"]
} else = "Microsoft.Cache/redis property 'minimumTlsVersion' need to be exist. Its missing from the resource. Please set the value to '1.2' after property addition." {
    azure_attribute_absence["min_tls_version_redis"]
}

min_tls_version_redis_metadata := {
    "Policy Code": "PR-AZR-CLD-ARC-007",
    "Type": "Cloud",  
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Azure Redis Cache has latest version of tls configured",
    "Policy Description": "This policy will identify the Azure Redis Cache which doesn't have the latest version of tls configured and give the alert",
    "Resource Type": "microsoft.cache/redis",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis"
}



#
# PR-AZR-CLD-ARC-008
#

default redis_cache_firewall_not_allowing_full_inbound_access = null


azure_attribute_absence ["redis_cache_firewall_not_allowing_full_inbound_access"] {
    count([c | lower(input.resources[_].type) == "microsoft.cache/redis/firewallrules"; c := 1]) == 0
}


azure_attribute_absence["sql_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis/firewallrules"
    not resource.dependsOn
}


azure_attribute_absence["redis_cache_firewall_not_allowing_full_inbound_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis/firewallrules"
    not resource.properties.startIP
}


azure_attribute_absence["redis_cache_firewall_not_allowing_full_inbound_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis/firewallrules"
    not resource.properties.endIP
}


azure_issue["redis_cache_firewall_not_allowing_full_inbound_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.cache/redis/firewallrules";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              not contains(r.properties.startIP, "0.0.0.0");
              not contains(r.properties.endIP, "0.0.0.0");
              c := 1]) == 0
}

redis_cache_firewall_not_allowing_full_inbound_access {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    not azure_attribute_absence["redis_cache_firewall_not_allowing_full_inbound_access"]
    not azure_issue["redis_cache_firewall_not_allowing_full_inbound_access"]
}

redis_cache_firewall_not_allowing_full_inbound_access = false {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    azure_attribute_absence["redis_cache_firewall_not_allowing_full_inbound_access"]
}

redis_cache_firewall_not_allowing_full_inbound_access = false {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    azure_issue["redis_cache_firewall_not_allowing_full_inbound_access"]
}

redis_cache_firewall_not_allowing_full_inbound_access_err = "microsoft.cache/redis/firewallrules resoruce or its property 'startIP' or 'endIP' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    azure_attribute_absence["redis_cache_firewall_not_allowing_full_inbound_access"]
} else = "Redis Cache firewall rule configuration currently allowing full inbound access to everyone" {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    azure_issue["redis_cache_firewall_not_allowing_full_inbound_access"]
}

redis_cache_firewall_not_allowing_full_inbound_access_metadata := {
    "Policy Code": "PR-AZR-CLD-ARC-008",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Redis Cache Firewall rules should not configure to allow full inbound access to everyone",
    "Policy Description": "Firewalls grant access to redis cache based on the originating IP address of each request and should be within the range of START IP and END IP. Firewall settings with START IP and END IP both with 0.0.0.0 represents access to all Azure internal network. This setting needs to be turned-off to remove blanket access.",
    "Resource Type": "microsoft.cache/redis",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis"
}