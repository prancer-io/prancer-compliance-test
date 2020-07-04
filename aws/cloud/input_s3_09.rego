package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html
# ID: 148

rulepass = false {
    policy := input.Policy.Statement[_]
    policy.Condition.Bool.aws:SecureTransport != true
    startswith(lower(policy.Action), "s3:")
    policy.Principal == "*"
    lower(policy.Effect) == "allow"
}

rulepass = false {
    policy := input.Policy.Statement[_]
    policy.Condition.Bool.aws:SecureTransport != true
    startswith(lower(policy.Action), "s3:")
    policy.Principal.AWS == "*"
    lower(policy.Effect) == "allow"
}
