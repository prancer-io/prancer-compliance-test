#
# PR-AWS-0139
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html

rulepass = false {
    lower(input.Type) == "aws::s3::bucket"
    policy := input.Policy.Statement[_]
    contains(lower(policy.Principal.Service), "cloudtrail")
    lower(policy.Effect) == "allow"
}
