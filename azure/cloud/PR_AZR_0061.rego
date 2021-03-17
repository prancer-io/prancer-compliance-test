#
# PR-AZR-0061
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/securityalertpolicies

rulepass {
   lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
   input.properties.state == "Enabled"
   count(input.properties.disabledAlerts) == 0
}
