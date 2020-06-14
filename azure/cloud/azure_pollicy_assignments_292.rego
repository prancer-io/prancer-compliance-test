package rule
default rulepass = true

# SQL auditing & Threat detection is set to OFF in Security Center
# If SQL auditing & Threat detection is set to ON in Security Center test will pass
# Auditing should be enabled on advanced data security settings on SQL server

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   input.properties.parameters.sqlServerAuditingMonitoringEffect.value == "Disabled"
}
