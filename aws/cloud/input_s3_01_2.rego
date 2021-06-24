#
# PR-AWS-0004
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLogging.html

rulepass {
    # lower(input.json.Type) == "aws::s3::bucket"	
    not is_null(input.json.LoggingEnabled.TargetBucket)
}

rulepass {
    # lower(input.json.Type) == "aws::s3::bucket"
    not input.json.LoggingEnabled.TargetPrefix=""
}

metadata := {
    "Policy Code": "PR-AWS-0004",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Access logging not enabled on S3 buckets",
    "Policy Description": "Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets. It is recommended that Access logging is turned on for all S3 buckets to meet audit PR-AWS-0004-DESC compliance requirement",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLogging.html"
}
