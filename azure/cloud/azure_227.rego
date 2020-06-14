package rule
default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/secrets

rulepass {
   to_number(input.properties.attributes.exp) > 0
}
