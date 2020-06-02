package rule

default rulepass = false

rulepass = true{
   input.Distribution.DistributionConfig.DefaultCacheBehavior.FieldLevelEncryptionId!=""
}
