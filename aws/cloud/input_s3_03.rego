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

metadata := {
    "Policy Code": "PR-AWS-0139",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS S3 Bucket Policy allows public access to CloudTrail logs",
    "Policy Description": "This policy scans your bucket policy that is applied to the S3 bucket to prevent public access to the CloudTrail logs. CloudTrail logs a record of every API call made in your AWS account. These logs file are stored in an S3 bucket. Bucket policy or the access control list (ACL) applied to the S3 bucket does not prevent public access to the CloudTrail logs. It is recommended that the bucket policy or access control list (ACL) applied to the S3 bucket that stores CloudTrail logs prevents public access. Allowing public access to CloudTrail log content may aid an adversary in identifying weaknesses in the affected account's use or configuration.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html"
}
