package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis

# PR-AZR-0110-ARM

default enableNonSslPort = null
azure_issue ["enableNonSslPort"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    resource.properties.enableNonSslPort != false
}

enableNonSslPort {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    not azure_issue["enableNonSslPort"]
}

enableNonSslPort = false {
    azure_issue["enableNonSslPort"]
}


enableNonSslPort_err = "ENSURE THAT THE REDIS CACHE ACCEPTS ONLY SSL CONNECTIONS" {
    azure_issue["enableNonSslPort"]
}


enableNonSslPort_metadata := {
    "Policy Code": "PR-AZR-0110-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "ENSURE THAT THE REDIS CACHE ACCEPTS ONLY SSL CONNECTIONS",
    "Policy Description": "
It is recommended that Redis Cache should allow only SSL connections. Note: some Redis tools (like redis-cli) do not support SSL. When using such tools plain connection ports should be enabled.",
    "Resource Type": "microsoft.cache/redis",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis
"
}