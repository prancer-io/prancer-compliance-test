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

alerts_err = "Send me emails about alerts is set to OFF in Security Center" {
    azure_issue["alerts"]
}

alerts_miss_err = "Activitylog alerts attribute enabled missing in the resource" {
    azure_attribute_absence["alerts"]
}
