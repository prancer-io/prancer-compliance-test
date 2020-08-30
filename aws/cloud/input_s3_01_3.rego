package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLogging.html
# ID: 147

rulepass {
   grant := input.Grants[_]
   not contains(lower(grant.Grantee.URI), "allusers")
}
