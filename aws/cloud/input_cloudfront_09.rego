package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_GetDistributionConfig.html
# Id: 30

rulepass = true{
   input.Distribution.DistributionConfig.Origins.Items[_].S3OriginConfig.OriginAccessIdentity!=""
}
