package rule
default rulepass = false

# Adaptive Application Controls is set to OFF in Security Center
# If Adaptive Application Controls is set to ON in Security Center

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    contains(input.id, "adaptiveApplicationControlsMonitoring")
}
