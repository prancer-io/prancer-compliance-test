#
# PR-AZR-0102
#

package rule
default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies
# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/securityalertpolicies

rulepass {
    input.properties.state == "Enabled"
}
