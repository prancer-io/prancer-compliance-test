package rule
default rulepass = true

# SQL Encryption is set to OFF in Security Center
# If SQL Encryption is set to ON in Security Center test will pass
# Transparent Data Encryption on SQL databases should be enabled

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   count(sql_encryption) == 1
}

#  properties.parameters.sqlDbEncryptionMonitoringEffect.value 

sql_encryption ["sql_encryption_set_on"] {
   input.properties.parameters.sqlDbEncryptionMonitoringEffect.value = "Disabled"
}