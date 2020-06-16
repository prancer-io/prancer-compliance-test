package rule

default rulepass = false

rulepass = true{
   input.Distribution.DistributionConfig.Restrictions.GeoRestriction.RestrictionType="whitelist"
}
