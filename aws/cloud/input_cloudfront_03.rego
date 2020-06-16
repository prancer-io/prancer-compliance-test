package rule

default rulepass = false

rulepass = true{
   input.Distribution.DistributionConfig.Logging.Enabled=true
   not is_null(input.Distribution.DistributionConfig.Logging.Bucket)
   input.Distribution.DistributionConfig.Logging.Bucket!=""
}
