package rule

# https://docs.microsoft.com/en-us/azure/templates/Microsoft.Cache/redis

# PR-AZR-0131-ARM

default serverRole = null

azure_attribute_absence ["serverRole"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    not resource.properties.enableNonSslPort
}

azure_issue ["serverRole"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    resource.properties.enableNonSslPort != false
}

serverRole {
    azure_attribute_absence["serverRole"]
}


serverRole {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    not azure_issue["serverRole"]
}


serverRole = false {
    azure_issue["serverRole"]
}

serverRole_err = "Azure Redis Cache enableNonSslPort is not false currently on the resource" {
    azure_issue["serverRole"]
}


serverRole_metadata := {
    "Policy Code": "PR-AZR-0131-ARM",
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

# PR-AZR-0132-ARM

default serverRole = null


azure_issue ["serverRole"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis/linkedservers"
    lower(resource.properties.serverRole) != "secondary"
}


serverRole {
    lower(input.resources[_].type) == "microsoft.cache/redis/linkedservers"
    not azure_issue["serverRole"]
}


serverRole = false {
    azure_issue["serverRole"]
}

serverRole_err = "Azure Redis Cache linked backup server currently does not have secondary role." {
    azure_issue["serverRole"]
}


serverRole_metadata := {
    "Policy Code": "PR-AZR-0132-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Redis cache should have a backup",
    "Policy Description": "Replicate Redis Cache server data to another Redis Cache server using geo replication. This feature is only available for Premium tier Redis Cache. From performance point of view, Microsoft recommends that both Redis Caches (Primary and the linked secondary) reside in the same region.",
    "Resource Type": "Microsoft.Cache/redis/linkedservers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis/linkedservers"
}