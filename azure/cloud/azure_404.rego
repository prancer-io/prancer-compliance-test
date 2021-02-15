#
# PR-AZR-0103
#

package rule
default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/auditingsettings

rulepass {
    input.properties.state == "Enabled"
}
