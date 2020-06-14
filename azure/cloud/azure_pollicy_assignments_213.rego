package rule
default rulepass = true

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {
   input.properties.parameters.ArcLinuxMonitoringEffect.value == "Disabled"
}

rulepass = false {
   input.properties.parameters.ArcWindowsMonitoringEffect.value == "Disabled"
}
