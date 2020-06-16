package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/securityalertpolicies

rulepass {
   input.properties.state == "Enabled"
   count(input.properties.disabledAlerts) == 0
}
