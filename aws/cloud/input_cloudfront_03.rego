#
# PR-AWS-0017
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html

rulepass = true {
    lower(input.Type) == "aws::cloudfront::distribution"
    input.Distribution.DistributionConfig.Logging.Enabled=true
    not is_null(input.Distribution.DistributionConfig.Logging.Bucket)
    input.Distribution.DistributionConfig.Logging.Bucket!=""
}

rulepass_metadata := {
    "Policy Code": "PR-AWS-0017",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS CloudFront distribution with access logging disabled",
    "Policy Description": "This policy identifies CloudFront distributions which have access logging disabled. Enabling access log on distributions creates log files that contain detailed information about every user request that CloudFront receives. Access logs are available for web distributions. If you enable logging, you can also specify the Amazon S3 bucket that you want CloudFront to save files in.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html"
}
