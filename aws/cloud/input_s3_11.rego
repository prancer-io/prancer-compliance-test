#
# PR-AWS-0150
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAcl.html

rulepass = false {
    lower(input.Type) == "aws::s3::bucket"
    grant := input.Grants[_]
    contains(lower(grant.Grantee.URI), "allusers")
}

metadata := {
    "Policy Code": "PR-AWS-0150",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS S3 buckets are accessible to public",
    "Policy Description": "This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.",
    "Compliance": ["CSA-CCM","GDPR","HITRUST","ISO 27001","NIST 800","PCI-DSS","SOC 2"],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAcl.html"
}
