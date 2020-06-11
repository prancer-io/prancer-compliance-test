package rule
default rulepass = true

# Adaptive Application Controls is set to OFF in Security Center
# If Adaptive Application Controls is set to ON in Security Center

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   count(adaptive_pollicy_assignments) == 1
}

#  properties.parameters.adaptiveApplicationControlsMonitoringEffect.value

adaptive_pollicy_assignments["adaptive_application_pollicy_assignments_set_on"] {
   input.properties.parameters.adaptiveApplicationControlsMonitoringEffect.value = "Disabled"
}