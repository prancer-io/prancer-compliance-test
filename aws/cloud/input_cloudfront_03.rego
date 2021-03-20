#
# PR-AWS-0017
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html

rulepass = true {
    lower(resource.Type) == "aws::cloudfront::distribution"
    input.Distribution.DistributionConfig.Logging.Enabled=true
    not is_null(input.Distribution.DistributionConfig.Logging.Bucket)
    input.Distribution.DistributionConfig.Logging.Bucket!=""
}
