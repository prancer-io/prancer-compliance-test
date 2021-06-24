#
# PR-AWS-0021
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html
# Id: 21

rulepass = true {
    # lower(input.Type) == "aws::cloudfront::distribution"
    input.Distribution.DistributionConfig.WebACLId!=""
}

metadata := {
    "Policy Code": "PR-AWS-0021",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS CloudFront web distribution with AWS Web Application Firewall (AWS WAF) service disabled",
    "Policy Description": "This policy identifies Amazon CloudFront web distributions which have the AWS Web Application Firewall (AWS WAF) service disabled. As a best practice, enable the AWS WAF service on CloudFront web distributions to protect against application layer attacks. To block malicious requests to your Cloudfront Content Delivery Network, define the block criteria in the WAF web access control list (web ACL).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html"
}
