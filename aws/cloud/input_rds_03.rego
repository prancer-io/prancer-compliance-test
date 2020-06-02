package rule

default rulepass = false

rulepass = true{
   db_instance := input.DBInstances[_]
   db_instance.CopyTagsToSnapshot == true
}

# If CopyTagsToSnapshot is enabled then test will pass.