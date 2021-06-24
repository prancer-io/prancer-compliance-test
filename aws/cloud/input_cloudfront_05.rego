#
# PR-AWS-0019
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html

rulepass = true {
    # lower(input.json.Type) == "aws::cloudfront::distribution"
    input.json.Distribution.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy=="https-only"
}

rulepass = true {
    # lower(input.json.Type) == "aws::cloudfront::distribution"
    input.json.Distribution.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy=="redirect-to-https"
}

metadata := {
    "Policy Code": "PR-AWS-0019",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS CloudFront viewer protocol policy is not configured with HTTPS",
    "Policy Description": "For web distributions, you can configure CloudFront to require that viewers use HTTPS to request your objects, so connections are encrypted when CloudFront communicates with viewers.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html"
}
