#
# PR-AZR-0001
#

package rule

default rulepass = true

# https://docs.microsoft.com/en-us/azure/azure-monitor/platform/template-workspace-configuration

rulepass = false {
    lower(input.type) == "microsoft.operationalinsights/workspaces"
    to_number(input.properties.retentionInDays) < 365
}
