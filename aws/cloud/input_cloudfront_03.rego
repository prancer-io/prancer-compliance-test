package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html
# Id: 17

rulepass = true{
   input.Distribution.DistributionConfig.Logging.Enabled=true
   not is_null(input.Distribution.DistributionConfig.Logging.Bucket)
   input.Distribution.DistributionConfig.Logging.Bucket!=""
}
