package rule

default rulepass = false

rulepass = true{
   not is_null(input.LoggingEnabled.TargetBucket)
}

rulepass = true{
   not input.LoggingEnabled.TargetPrefix=""
}
