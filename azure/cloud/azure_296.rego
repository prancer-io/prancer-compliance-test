package rule
default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts

rulepass {                                      
   contains(input.properties.email, "@")
   contains(input.properties.email, ".")
}
