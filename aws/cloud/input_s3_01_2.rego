package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLogging.html
# ID: 4

rulepass {
   not is_null(input.LoggingEnabled.TargetBucket)
}

rulepass {
   not input.LoggingEnabled.TargetPrefix=""
}
