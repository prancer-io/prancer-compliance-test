package rule

default rulepass = false

rulepass = true{
   input.trailList[_].KmsKeyId
}
