package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/secrets

#
# Azure Key Vault secrets have no expiration date (227)
#

default kv_expire = null

kv_expire {
    lower(input.type) == "microsoft.keyvault/vaults/secrets"
    to_number(input.properties.attributes.exp) > 0
}

kv_expire = false {
    lower(input.type) == "microsoft.keyvault/vaults/secrets"
    to_number(input.properties.attributes.exp) == 0
}

kv_expire = false {
    lower(input.type) == "microsoft.keyvault/vaults/secrets"
    count([c | input.properties.attributes.exp; c := 1]) == 0
}

kv_expire_err = "Azure Key Vault secrets have no expiration date" {
    kv_expire == false
}
