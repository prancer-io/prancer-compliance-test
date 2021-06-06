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

metadata := {
    "Policy Code": "PR-AZR-0001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Activity Log Retention should not be set to less than 365 days",
    "Policy Description": "A Log Profile controls how your Activity Log is exported and retained. Since the average time to detect a breach is over 200 days, it is recommended to retain your activity log for 365 days or more in order to have time to respond to any incidents.",
    "Resource Type": "microsoft.operationalinsights/workspaces",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/azure-monitor/platform/template-workspace-configuration"
}
