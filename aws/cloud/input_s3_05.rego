#
# PR-AWS-0141
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html

rulepass = false {
   policy := input.Policy.Statement[_]
   policy.Principal == "*"
   startswith(lower(policy.Action), "s3:get")
   lower(policy.Effect) == "allow"
}

rulepass = false {
   policy := input.Policy.Statement[_]
   policy.Principal == "*"
   policy.Action == "*"
   lower(policy.Effect) == "allow"
}

rulepass = false {
   policy := input.Policy.Statement[_]
   policy.Principal.AWS == "*"
   startswith(lower(policy.Action), "s3:get")
   lower(policy.Effect) == "allow"
}

rulepass = false {
   policy := input.Policy.Statement[_]
   policy.Principal.AWS == "*"
   policy.Action == "*"
   lower(policy.Effect) == "allow"
}
