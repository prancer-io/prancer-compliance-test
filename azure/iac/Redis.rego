package rule

# https://docs.microsoft.com/en-us/azure/templates/Microsoft.Cache/redis

# PR-AZR-ARM-ARC-001

default enableSslPort = null
# default is false
azure_attribute_absence ["enableSslPort"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    not resource.properties.enableNonSslPort
}

azure_issue ["enableSslPort"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    resource.properties.enableNonSslPort != false
}

enableSslPort {
    azure_attribute_absence["enableSslPort"]
    not azure_issue["enableSslPort"]
}

enableSslPort {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    not azure_issue["enableSslPort"]
}

enableSslPort = false {
    azure_issue["enableSslPort"]
}

enableSslPort_err = "Redis cache is currently allowing unsecure connection via a non ssl port opened" {
    azure_issue["enableSslPort"]
}

enableSslPort_metadata := {
    "Policy Code": "PR-AZR-ARM-ARC-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that the Redis Cache accepts only SSL connections",
    "Policy Description": "It is recommended that Redis Cache should allow only SSL connections. Note: some Redis tools (like redis-cli) do not support SSL. When using such tools plain connection ports should be enabled.",
    "Resource Type": "Microsoft.Cache/redis",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/Microsoft.Cache/redis"
}


# https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis/linkedservers

# PR-AZR-ARM-ARC-002

default serverRole = null

azure_attribute_absence ["serverRole"] {
    resource := input.resources[i]
    count([c | resource.type == "microsoft.cache/redis"; c := 1]) != count([c | resource.type == "microsoft.cache/redis/linkedservers"; c := 1])
}

source_path[{"serverRole":metadata}] {
    resource := input.resources[i]
    count([c | resource.type == "microsoft.cache/redis"; c := 1]) != count([c | resource.type == "microsoft.cache/redis/linkedservers"; c := 1])
    metadata:= {
        "resource_path": [["resources",i,"type"]]
    }
}

# as linkedservers is child resource of microsoft.cache/redis, we need to make sure microsoft.cache/redis exist in the same template first.
# azure_attribute_absence["serverRole"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.cache/redis"
#     count([c | input.resources[_].type == "microsoft.cache/redis/linkedservers";
#     	   c := 1]) == 0
# }

azure_attribute_absence ["serverRole"] {
   resource := input.resources[_]
   lower(resource.type) == "microsoft.cache/redis/linkedservers"
   not resource.properties.serverRole
}


source_path[{"serverRole":metadata}] {
   resource := input.resources[i]
   lower(resource.type) == "microsoft.cache/redis/linkedservers"
   not resource.properties.serverRole
   metadata:= {
        "resource_path": [["resources",i,"properties","serverRole"]]
    }
}

azure_issue ["serverRole"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis/linkedservers"
    lower(resource.properties.serverRole) != "secondary"
}

source_path[{"serverRole":metadata}] {
   resource := input.resources[i]
   lower(resource.type) == "microsoft.cache/redis/linkedservers"
    lower(resource.properties.serverRole) != "secondary"
   metadata:= {
        "resource_path": [["resources",i,"properties","serverRole"]]
    }
}


serverRole {
    lower(input.resources[_].type) == "microsoft.cache/redis/linkedservers"
    not azure_attribute_absence["serverRole"]
    not azure_issue["serverRole"]
}


serverRole = false {
    azure_attribute_absence["serverRole"]
}


serverRole = false {
    azure_issue["serverRole"]
}

serverRole_miss_err = "Azure Redis Cache linked server property 'serverRole' is missing from the resource" {
    azure_attribute_absence["serverRole"]
}

serverRole_err = "Azure Redis Cache linked backup server currently does not have secondary role." {
    azure_issue["serverRole"]
}

serverRole_metadata := {
    "Policy Code": "PR-AZR-ARM-ARC-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Redis cache should have a backup",
    "Policy Description": "Replicate Redis Cache server data to another Redis Cache server using geo replication. This feature is only available for Premium tier Redis Cache. From performance point of view, Microsoft recommends that both Redis Caches (Primary and the linked secondary) reside in the same region.",
    "Resource Type": "Microsoft.Cache/redis/linkedservers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis/linkedservers"
}



# PR-AZR-ARM-ARC-004

default redis_public_access = null


azure_attribute_absence["redis_public_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    not resource.properties.publicNetworkAccess
}

source_path[{"redis_public_access":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.cache/redis"
    not resource.properties.publicNetworkAccess
    metadata:= {
        "resource_path": [["resources",i,"properties","publicNetworkAccess"]]
    }
}

azure_issue["redis_public_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    lower(resource.properties.publicNetworkAccess) != "disabled"
}

source_path[{"redis_public_access":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.cache/redis"
    lower(resource.properties.publicNetworkAccess) != "disabled"
    metadata:= {
        "resource_path": [["resources",i,"properties","publicNetworkAccess"]]
    }
}


redis_public_access {
    azure_attribute_absence["redis_public_access"]
}

redis_public_access {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    not azure_attribute_absence["redis_public_access"]
    not azure_issue["redis_public_access"]
}

redis_public_access = false {
    azure_issue["redis_public_access"]
}

redis_public_access_err = "Azure Redis Cache with public access detected!" {
    azure_issue["redis_public_access"]
}

redis_public_access_metadata := {
    "Policy Code": "PR-AZR-ARM-ARC-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Cache for Redis should disable public network access",
    "Policy Description": "Disabling public network access improves security by ensuring that the Azure Cache for Redis isn't exposed on the public internet. You can limit exposure of your Azure Cache for Redis by creating private endpoints instead. Learn more at: https://docs.microsoft.com/azure/azure-cache-for-redis/cache-private-link.",
    "Resource Type": "microsoft.cache/redis",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis"
}


# PR-AZR-ARM-ARC-005
#

default arc_subnet_id = null

azure_attribute_absence["arc_subnet_id"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    not resource.properties.subnetId
}

source_path[{"arc_subnet_id":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.cache/redis"
    not resource.properties.subnetId
    metadata:= {
        "resource_path": [["resources",i,"properties","subnetId"]]
    }
}


azure_issue["arc_subnet_id"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    count(resource.properties.subnetId) == 0
}


source_path[{"arc_subnet_id":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.cache/redis"
    count(resource.properties.subnetId) == 0
    metadata:= {
        "resource_path": [["resources",i,"properties","subnetId"]]
    }
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
    "Policy Code": "PR-AZR-ARM-ARC-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Cache for Redis should use private link",
    "Policy Description": "Azure Virtual Network deployment provides enhanced security and isolation for your Azure Cache for Redis, as well as subnets, access control policies, and other features to further restrict access.When an Azure Cache for Redis instance is configured with a virtual network, it is not publicly addressable and can only be accessed from virtual machines and applications within the virtual network.",
    "Resource Type": "microsoft.cache/redis",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis"
}