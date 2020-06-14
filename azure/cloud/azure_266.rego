package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/vulnerabilityassessments

rulepass {
   input.properties.recurringScans.isEnabled == true
   input.properties.recurringScans.emailSubscriptionAdmins == true
}
