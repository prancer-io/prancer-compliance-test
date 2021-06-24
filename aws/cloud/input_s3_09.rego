#
# PR-AWS-0148
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html

rulepass = false {
    # lower(input.Type) == "aws::s3::bucket"
    policy := input.Policy.Statement[_]
    policy.Condition.Bool.aws:SecureTransport != true
    startswith(lower(policy.Action), "s3:")
    policy.Principal == "*"
    lower(policy.Effect) == "allow"
}

rulepass = false {
    # lower(input.Type) == "aws::s3::bucket"
    policy := input.Policy.Statement[_]
    policy.Condition.Bool.aws:SecureTransport != true
    startswith(lower(policy.Action), "s3:")
    policy.Principal.AWS == "*"
    lower(policy.Effect) == "allow"
}

metadata := {
    "Policy Code": "PR-AWS-0148",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS S3 bucket not configured with secure data transport policy",
    "Policy Description": "This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html"
}
