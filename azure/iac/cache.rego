package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis

# PR-AZR-0110-ARM

default enableNonSslPort = null

azure_attribute_absence ["enableNonSslPort"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    not resource.properties.enableNonSslPort
}

azure_issue ["enableNonSslPort"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    resource.properties.enableNonSslPort != false
}

enableNonSslPort {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    not azure_issue["enableNonSslPort"]
    not azure_attribute_absence["enableNonSslPort"]
}

enableNonSslPort = false {
    azure_attribute_absence["enableNonSslPort"]
}

enableNonSslPort = false {
    azure_issue["enableNonSslPort"]
}


enableNonSslPort_err = "Ensure that the Redis Cache accepts only SSL connections" {
    azure_issue["enableNonSslPort"]
}

enableNonSslPort_miss_err = "Ensure that the Redis Cache accepts only SSL connections" {
    azure_attribute_absence["enableNonSslPort"]
}


enableNonSslPort_metadata := {
    "Policy Code": "PR-AZR-0110-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that the Redis Cache accepts only SSL connections",
    "Policy Description": "It is recommended that Redis Cache should allow only SSL connections. Note: some Redis tools (like redis-cli) do not support SSL. When using such tools plain connection ports should be enabled.",
    "Resource Type": "microsoft.cache/redis",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis"
}