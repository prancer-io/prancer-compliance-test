#
# PR-AWS-0015
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html

rulepass = true {
    lower(input.Type) == "aws::cloudfront::distribution"
    input.Distribution.DistributionConfig.DefaultCacheBehavior.FieldLevelEncryptionId! == ""
}

rulepass_metadata := {
    "Policy Code": "PR-AWS-0015",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS CloudFront Distributions with Field-Level Encryption not enabled",
    "Policy Description": "This policy identifies CloudFront distributions for which field-level encryption is not enabled. Field-level encryption adds an additional layer of security along with HTTPS which protects specific data throughout system processing so that only certain applications can see it.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html"
}
