package rule

default rulepass = false

rulepass = true {
    instance := input.DBInstances[_]
    instance.MultiAZ
    instance.MultiAZ=true
}

# If multi availability zone is enabled then test will pass.