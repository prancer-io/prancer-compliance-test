#
# PR-AWS-0150
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAcl.html

rulepass = false {
    lower(input.Type) == "aws::s3::bucket"
    grant := input.Grants[_]
    contains(lower(grant.Grantee.URI), "allusers")
}
