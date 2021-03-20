#
# PR-AWS-0021
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html
# Id: 21

rulepass = true{
    lower(resource.Type) == "aws::cloudfront::distribution"
   input.Distribution.DistributionConfig.WebACLId!=""
}
