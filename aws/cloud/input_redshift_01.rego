package rule

default rulepass = false

rulepass = true{
   input.Clusters[_].Encrypted=true
}
