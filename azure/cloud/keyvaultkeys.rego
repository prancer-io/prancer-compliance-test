package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/keys

#
# PR-AZR-CLD-KV-004
#

default kv_keys_expire = null

azure_attribute_absence["kv_keys_expire"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults/keys"
    #create seperate rule with this property
    #resource.properties.attributes.enabled != false
    not resource.properties.attributes.exp
    #create seperate rule with this property
    #not resource.properties.rotationPolicy.attributes.expiryTime
}

azure_issue["kv_keys_expire"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults/keys"
    #resource.properties.attributes.enabled != false
    to_number(resource.properties.attributes.exp) < 0
    #count(resource.properties.rotationPolicy.attributes.expiryTime) == 0
}


kv_keys_expire {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults/keys"
    not azure_attribute_absence["kv_keys_expire"]
    not azure_issue["kv_keys_expire"]
}


kv_keys_expire = false {
    azure_attribute_absence["kv_keys_expire"]
}

kv_keys_expire = false {
    azure_issue["kv_keys_expire"]
}


kv_keys_expire_miss_err = "Azure Key Vault attribute 'exp' or 'expiryTime' is missing from the resource" {
    azure_attribute_absence["kv_keys_expire"]
}

kv_keys_expire_err = "Azure Key Vault keys currently dont have any expiration date" {
    azure_issue["kv_keys_expire"]
}


kv_keys_expire_metadata := {
    "Policy Code": "PR-AZR-CLD-KV-004",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Key Vault keys should have an expiration date",
    "Policy Description": "This policy identifies Azure Key Vault keys that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.",
    "Resource Type": "microsoft.keyvault/vaults/keys",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/keys"
}
