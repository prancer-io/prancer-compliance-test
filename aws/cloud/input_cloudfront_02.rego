#
# PR-AWS-0016
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html

rulepass = true {
    # lower(input.json.Type) == "aws::cloudfront::distribution"
    input.json.Distribution.DistributionConfig.Origins.Items[_].CustomOriginConfig.OriginSslProtocols.Items[_]!="SSLv3"
}

metadata := {
    "Policy Code": "PR-AWS-0016",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS CloudFront distribution is using insecure SSL protocols for HTTPS communication",
    "Policy Description": "CloudFront, a content delivery network (CDN) offered by AWS, is not using a secure cipher for distribution. It is a best security practice to enforce the use of secure ciphers TLSv1.0, TLSv1.1, and/or TLSv1.2 in a CloudFront Distribution's certificate configuration. This policy scans for any deviations from this practice and returns the results.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html"
}


