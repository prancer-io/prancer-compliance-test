#
# PR-AWS-0141
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html

rulepass = false {
    lower(input.Type) == "aws::s3::bucket"
    policy := input.Policy.Statement[_]
    policy.Principal == "*"
    startswith(lower(policy.Action), "s3:get")
    lower(policy.Effect) == "allow"
}

rulepass = false {
    lower(input.Type) == "aws::s3::bucket"
    policy := input.Policy.Statement[_]
    policy.Principal == "*"
    policy.Action == "*"
    lower(policy.Effect) == "allow"
}

rulepass = false {
    lower(input.Type) == "aws::s3::bucket"
    policy := input.Policy.Statement[_]
    policy.Principal.AWS == "*"
    startswith(lower(policy.Action), "s3:get")
    lower(policy.Effect) == "allow"
}

rulepass = false {
    lower(input.Type) == "aws::s3::bucket"
    policy := input.Policy.Statement[_]
    policy.Principal.AWS == "*"
    policy.Action == "*"
    lower(policy.Effect) == "allow"
}

metadata := {
    "Policy Code": "PR-AWS-0141",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS S3 Bucket has Global GET Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html"
}
