#
# PR-AZR-0063
#

package rule
default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-05-01-preview/diagnosticsettings

rulepass {
    lower(input.type) == "microsoft.insights/diagnosticsettings"
    logs := input.properties.logs[_]
    logs.category == "AuditEvent"
    logs.enabled == true
    logs.retentionPolicy.enabled == true
    logs.retentionPolicy.days >= 90
}
