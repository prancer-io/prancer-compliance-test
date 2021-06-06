#
# PR-AWS-0018
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html

rulepass = true {
    lower(input.Type) == "aws::cloudfront::distribution"
    input.Distribution.DistributionConfig.Origins.Items[_].CustomOriginConfig.OriginProtocolPolicy=="https-only"
}

rulepass_metadata := {
    "Policy Code": "PR-AWS-0018",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS CloudFront origin protocol policy does not enforce HTTPS-only",
    "Policy Description": "It is a best security practice to enforce HTTPS-only traffic between a CloudFront distribution and the origin. This policy scans for any deviations from this practice and returns the results.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html"
}
