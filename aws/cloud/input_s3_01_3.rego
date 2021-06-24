#
# PR-AWS-0147
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLogging.html

rulepass {
    # lower(input.json.Type) == "aws::s3::bucket"
    grant := input.json.Grants[_]
    not contains(lower(grant.Grantee.URI), "allusers")
}

metadata := {
    "Policy Code": "PR-AWS-0147",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS S3 bucket has global view ACL permissions enabled",
    "Policy Description": "This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLogging.html"
}
