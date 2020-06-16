package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/azure-monitor/platform/template-workspace-configuration

rulepass {
   resources := input.resources[_]
   resources.type == "Microsoft.OperationalInsights/workspaces"
   to_number(resources.properties.retentionInDays) >= 365
}
