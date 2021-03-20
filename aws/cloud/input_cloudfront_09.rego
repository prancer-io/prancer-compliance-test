#
# PR-AWS-0030
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_GetDistributionConfig.html

rulepass = true{
    lower(resource.Type) == "aws::cloudfront::distribution"
    input.Distribution.DistributionConfig.Origins.Items[_].S3OriginConfig.OriginAccessIdentity!=""
}
