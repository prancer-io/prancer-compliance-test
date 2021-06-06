#
# PR-AWS-0196
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketWebsite.html

rulepass = false {
    lower(input.Type) == "aws::s3::bucket"
    input.Website
}

rulepass == false {
    lower(input.Type) == "aws::s3::bucket"
    input.WebsiteConfiguration
}

metadata := {
    "Policy Code": "PR-AWS-0196",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "S3 buckets with configurations set to host websites",
    "Policy Description": "To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketWebsite.html"
}
