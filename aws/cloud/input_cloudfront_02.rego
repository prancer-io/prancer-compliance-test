package rule

default rulepass = false

rulepass = true{
   input.Distribution.DistributionConfig.Origins.Items[_].CustomOriginConfig.OriginSslProtocols.Items[_]!="SSLv3"
}


