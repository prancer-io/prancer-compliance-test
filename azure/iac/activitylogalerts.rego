package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-04-01/activitylogalerts

#
# PR-AZR-0090-ARM
#

default alerts = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.enabled
}

azure_issue["alerts"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    resource.properties.enabled != true
}

alerts {
    azure_attribute_absence["alerts"]
}

alerts {
    lower(input.resources[_].type) == "microsoft.insights/activitylogalerts"
    not azure_attribute_absence["alerts"]
    not azure_issue["alerts"]
}

alerts = false {
    azure_issue["alerts"]
}

alerts_err = "Activity log alerts is not enabled" {
    azure_issue["alerts"]
}

alerts_metadata := {
    "Policy Code": "PR-AZR-0090-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Activity log alerts should be enabled",
    "Policy Description": "Activity log alerts are alerts that activate when a new activity log event occurs that matches the conditions specified in the alert. Based on the order and volume of the events recorded in Azure activity log, the alert rule will fire. Enabling Activity log alerts will allow Azure to send you emails about any high severity alerts in your environment. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.",
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-04-01/activitylogalerts"
}
