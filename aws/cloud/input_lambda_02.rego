package rule

default rulepass = false

rulepass = true{
   input.Configuration.VpcConfig
   input.Configuration.VpcConfig.VpcId
}

#If the VPC network is configured with LAMBDA then test will pass