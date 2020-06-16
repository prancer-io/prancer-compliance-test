package rule

default rulepass = false

rulepass = true{
   input.Distribution.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy=="https-only"
}

rulepass = true{
   input.Distribution.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy=="redirect-to-https"
}