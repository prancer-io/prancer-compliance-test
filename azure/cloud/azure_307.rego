package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/vpngateways

rulepass {
   input.properties.networkAcls.defaultAction == "Deny"
}
