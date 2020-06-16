package rule

default rulepass = false

rulepass = true{
   input.Distribution.DistributionConfig.Origins.Items[_].S3OriginConfig.OriginAccessIdentity!=""
}
