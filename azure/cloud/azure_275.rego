package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/virtualnetworks/subnets

rulepass {                                      
   input.properties.networkSecurityGroup.id
}
