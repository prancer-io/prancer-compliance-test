package rule

default rulepass = false

rulepass = true{
   db_instance := input.DBInstances[_]
   db_instance.PubliclyAccessible == false
}

# If database instance publicly accessible is disabled then test will pass.