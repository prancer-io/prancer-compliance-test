package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html
# Id: 15

rulepass = true{
   input.Distribution.DistributionConfig.DefaultCacheBehavior.FieldLevelEncryptionId!=""
}
