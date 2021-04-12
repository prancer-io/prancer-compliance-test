#
# PR-AZR-0059
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/auditingsettings

rulepass {
    lower(input.type) == "microsoft.sql/servers/databases/auditingsettings"
    input.properties.state == "Enabled"
    input.properties.retentionDays > 90
}
