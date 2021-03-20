#
# PR-AWS-0018
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html

rulepass = true{
    lower(resource.Type) == "aws::cloudfront::distribution"
   input.Distribution.DistributionConfig.Origins.Items[_].CustomOriginConfig.OriginProtocolPolicy=="https-only"
}
