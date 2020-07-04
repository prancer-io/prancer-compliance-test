package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html
# ID: 145

rulepass = false {
   lower(input.Versioning.Status) == "disabled"
}
