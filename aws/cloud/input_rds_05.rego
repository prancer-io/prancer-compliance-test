package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html
# Id: 127

rulepass {
    instance := input.DBInstances[_]
    instance.MultiAZ
    instance.MultiAZ == true
}

# If multi availability zone is enabled then test will pass.
