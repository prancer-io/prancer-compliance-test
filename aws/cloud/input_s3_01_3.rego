#
# PR-AWS-0147
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLogging.html

rulepass {
   grant := input.Grants[_]
   not contains(lower(grant.Grantee.URI), "allusers")
}
