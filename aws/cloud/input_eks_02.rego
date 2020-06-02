package rule

default rulepass = false

rulepass = true{
   	input.cluster.logging.clusterLogging[_].enabled=true
}
