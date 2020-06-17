package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLogging.html
# ID: 147

rulepass = true{
   grant := input.Grants[_]
   not contains(grant.Grantee.URI, "AllUsers")
}