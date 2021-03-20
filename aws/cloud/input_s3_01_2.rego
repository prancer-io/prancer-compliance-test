#
# PR-AWS-0004
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLogging.html

rulepass {
    lower(resource.Type) == "aws::s3::bucket"	
    not is_null(input.LoggingEnabled.TargetBucket)
}

rulepass {
    lower(resource.Type) == "aws::s3::bucket"
    not input.LoggingEnabled.TargetPrefix=""
}
