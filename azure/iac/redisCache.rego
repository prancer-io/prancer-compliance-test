package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis/linkedservers

# PR-AZR-0116-ARM

default severRole = null

azure_issue["severRole"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis/linkedservers"
    lower(resource.properties.serverRole) != "secondary"
}

severRole {
    lower(input.resources[_].type) == "microsoft.cache/redis/linkedservers"
    not azure_issue["severRole"]
}

severRole = false {
    azure_issue["severRole"]
}

severRole_err = "" {
    azure_issue["severRole"]
}

severRole_metadata := {
    "Policy Code": "PR-AZR-0116-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Redis cache should have a backup",
    "Policy Description": "Replicate Redis Cache server data to another Redis Cache server using geo replication. This feature is only available for Premium tier Redis Cache. From performance point of view, Microsoft recommends that both Redis Caches (Primary and the linked secondary) reside in the same region.",
    "Resource Type": "microsoft.cache/redis/linkedservers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis/linkedservers"
}
