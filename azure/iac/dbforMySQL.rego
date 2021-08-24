package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformysql/servers

# PR-AZR-0147-ARM

default ssl_enforcement = null
azure_attribute_absence ["ssl_enforcement"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers"
    not resource.properties.sslEnforcement
}

azure_issue ["ssl_enforcement"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers"
    lower(resource.properties.sslEnforcement) != "enabled"
}

ssl_enforcement {
    lower(input.resources[_].type) == "microsoft.dbformysql/servers"
    not azure_attribute_absence["ssl_enforcement"]
    not azure_issue["ssl_enforcement"]
}

ssl_enforcement = false {
    azure_issue["ssl_enforcement"]
}

ssl_enforcement = false {
    azure_attribute_absence["ssl_enforcement"]
}


ssl_enforcement_err = "Either ssl enforcement is absent or disabled on MySQL server databases." {
    azure_attribute_absence["ssl_enforcement"]
} else = "Property ssl_enforcement of type enum is absent from resource of type microsoft.dbformysql/servers" {
    azure_issue["ssl_enforcement"]
}

ssl_enforcement_metadata := {
    "Policy Code": "PR-AZR-0147-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure ssl enforcement is enabled on MySQL server Database Server.",
    "Policy Description": "Enable SSL connection on MySQL Servers databases. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.",
    "Resource Type": "microsoft.dbformysql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformysql/servers"
}