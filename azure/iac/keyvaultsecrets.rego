package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/secrets

#
# PR-AZR-0018-ARM
#

default kv_expire = null

azure_attribute_absence["kv_expire"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults/secrets"
    resource.properties.attributes.enabled != false
    not resource.properties.attributes.exp
}

azure_issue["kv_expire"] {
    resource := input.resources[_]
    resource.properties.attributes.enabled != false
    #Expiry date in seconds since 1970-01-01T00:00:00Z.
    to_number(resource.properties.attributes.exp) < 0
}

kv_expire {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults/secrets"
    not azure_attribute_absence["kv_expire"]
    not azure_issue["kv_expire"]
}

kv_expire = false {
    azure_issue["kv_expire"]
}

kv_expire = false {
    azure_attribute_absence["kv_expire"]
}

kv_expire_err = "Azure Key Vault secrets currently dont have any expiration date" {
    azure_issue["kv_expire"]
}

kv_expire_miss_err = "Azure Key Vault attribute 'exp' is missing from the resource" {
    azure_attribute_absence["kv_expire"]
}

kv_expire_metadata := {
    "Policy Code": "PR-AZR-0018-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Key Vault secrets should have an expiration date",
    "Policy Description": "This policy identifies Azure Key Vault secrets that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.",
    "Resource Type": "microsoft.keyvault/vaults/secrets",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/secrets"
}
