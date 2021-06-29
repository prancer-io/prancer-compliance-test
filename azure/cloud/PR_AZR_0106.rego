package rule

# https://docs.microsoft.com/en-us/rest/api/postgresql/singleserver/servers/get
# PR_AZR_0106.rego

default sslEnforcement = null
azure_issue ["sslEnforcement"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    resource.properties.sslEnforcement != "Enabled"
}

sslEnforcement {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    not azure_issue["sslEnforcement"]
}

sslEnforcement = false {
    azure_issue["sslEnforcement"]
}


sslEnforcement_err = "ENSURE 'ENFORCE SSL CONNECTION' IS SET TO 'ENABLED' FOR POSTGRESQL DATABASE SERVER" {
    azure_issue["sslEnforcement"]
}


sslEnforcement_metadata := {
    "Policy Code": "PR-AZR-0106",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "ENSURE 'ENFORCE SSL CONNECTION' IS SET TO 'ENABLED' FOR POSTGRESQL DATABASE SERVER",
    "Policy Description": "Enable SSL connection on PostgreSQL Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.",
    "Resource Type": "microsoft.dbforpostgresql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/postgresql/singleserver/servers/get"
}