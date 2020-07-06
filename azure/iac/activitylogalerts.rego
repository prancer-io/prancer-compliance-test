package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-04-01/activitylogalerts

#
# Send me emails about alerts is set to OFF in Security Center (299)
#

default alerts = null

alerts {
    lower(input.type) == "microsoft.insights/activitylogalerts"
    input.properties.enabled == true
}

alerts = false {
    lower(input.type) == "microsoft.insights/activitylogalerts"
    input.properties.enabled != true
}

alerts_err = "Send me emails about alerts is set to OFF in Security Center" {
    alerts == false
}
