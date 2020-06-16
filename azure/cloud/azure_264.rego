package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies

rulepass {
   input.properties.state == "Enabled"
   input.properties.emailAccountAdmins == true
   count(input.properties.emailAddresses) > 0
}
