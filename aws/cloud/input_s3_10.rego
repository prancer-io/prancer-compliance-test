package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAcl.html
# ID: 149

rulepass = false {
    grant := input.Grants[_]
    contains(lower(grant.Grantee.URI), "authenticatedusers")
}
