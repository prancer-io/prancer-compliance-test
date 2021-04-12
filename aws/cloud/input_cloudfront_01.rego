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
