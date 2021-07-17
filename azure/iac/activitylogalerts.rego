package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-04-01/activitylogalerts

#
# PR-AZR-0090-ARM
#

default alerts = null

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
    lower(input.resources[_].type) == "microsoft.insights/activitylogalerts"
    not azure_issue["alerts"]
    not azure_attribute_absence["alerts"]
}

alerts = false {
    azure_issue["alerts"]
}

alerts = false {
    azure_attribute_absence["alerts"]
}

alerts_err = "Activity log alerts should be enabled" {
    azure_issue["alerts"]
}

alerts_miss_err = "enabled attribute of Activity log alerts is missing" {
    azure_attribute_absence["alerts"]
}

alerts_metadata := {
    "Policy Code": "PR-AZR-0090-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Activity log alerts should be enabled",
    "Policy Description": "The Activity log is a platform log in Azure that provides insight into subscription-level events. This includes such information as when a resource is modified or when a virtual machine is started. Enabling Activity log alerts will allow Azure to send you emails about any high severity alerts in your environment. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.",
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-04-01/activitylogalerts"
}
