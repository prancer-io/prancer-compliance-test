package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache

# PR-AZR-0131-TRF

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
    azure_attribute_absence["enableSslPort"]
}

enableSslPort {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    not azure_issue["servenableSslPorterRole"]
}

enableSslPort = false {
    azure_issue["enableSslPort"]
}

enableSslPort_err = "Redis cache is currently allowing unsecure connection via a non ssl port opened" {
    azure_issue["enableSslPort"]
}

enableSslPort_metadata := {
    "Policy Code": "PR-AZR-0131-TRF",
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

# PR-AZR-0132-TRF

default serverRole = null

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

serverRole {
    lower(input.resources[_].type) == "azurerm_redis_linked_server"
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
    "Policy Code": "PR-AZR-0132-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Redis cache should have a backup",
    "Policy Description": "Replicate Redis Cache server data to another Redis Cache server using geo replication. This feature is only available for Premium tier Redis Cache. From performance point of view, Microsoft recommends that both Redis Caches (Primary and the linked secondary) reside in the same region.",
    "Resource Type": "azurerm_redis_linked_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_linked_server"
}