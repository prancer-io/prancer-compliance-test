package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html
# Id: 19

rulepass = true{
   input.Distribution.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy=="https-only"
}

rulepass = true{
   input.Distribution.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy=="redirect-to-https"
}