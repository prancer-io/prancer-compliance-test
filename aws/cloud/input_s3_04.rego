#
# PR-AWS-0140
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html

rulepass = false {
    lower(resource.Type) == "aws::s3::bucket"
   policy := input.Policy.Statement[_]
   policy.Principal == "*"
   startswith(lower(policy.Action), "s3:delete")
   lower(policy.Effect) == "allow"
}

rulepass = false {
    lower(resource.Type) == "aws::s3::bucket"
   policy := input.Policy.Statement[_]
   policy.Principal == "*"
   policy.Action == "*"
   lower(policy.Effect) == "allow"
}

rulepass = false {
    lower(resource.Type) == "aws::s3::bucket"
   policy := input.Policy.Statement[_]
   policy.Principal.AWS == "*"
   startswith(lower(policy.Action), "s3:delete")
   lower(policy.Effect) == "allow"
}

rulepass = false {
    lower(resource.Type) == "aws::s3::bucket"
   policy := input.Policy.Statement[_]
   policy.Principal.AWS == "*"
   policy.Action == "*"
   lower(policy.Effect) == "allow"
}
