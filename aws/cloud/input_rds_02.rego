package rule

default rulepass = false

rulepass = true{
   db_instance := input.DBInstances[_]
   db_instance.StorageEncrypted == true
}

# If storage encryption is set to enabled then test will pass.