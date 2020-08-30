package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html
# ID: 139

rulepass = false {
   policy := input.Policy.Statement[_]
   contains(lower(policy.Principal.Service), "cloudtrail")
   lower(policy.Effect) == "allow"
}
