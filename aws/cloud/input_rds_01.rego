package rule

default rulepass = false

rulepass = true{
   db_instance := input.DBInstances[_]
   db_instance.BackupRetentionPeriod > 0
}

# If BackupRetentionPeriod is set for database instance then test will pass.