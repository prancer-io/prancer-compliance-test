package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html
# Id: 23

rulepass = true{
   input.Distribution.DistributionConfig.Restrictions.GeoRestriction.RestrictionType="whitelist"
}
