package rule

default rulepass = false

rulepass = true{
   	input.cluster.resourcesVpcConfig.endpointPrivateAccess=true
    input.cluster.resourcesVpcConfig.endpointPublicAccess=false
}