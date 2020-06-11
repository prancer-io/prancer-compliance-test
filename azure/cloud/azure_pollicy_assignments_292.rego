package rule
default rulepass = true

# SQL auditing & Threat detection is set to OFF in Security Center
# If SQL auditing & Threat detection is set to ON in Security Center test will pass
# Auditing should be enabled on advanced data security settings on SQL server

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   count(sql_auditing_threat_detection) == 1
}

#  properties.parameters.sqlServerAuditingMonitoringEffect.value 

sql_auditing_threat_detection["sql_auditing_threat_detection_access_set_on"] {
   input.properties.parameters.sqlServerAuditingMonitoringEffect.value = "Disabled"
}