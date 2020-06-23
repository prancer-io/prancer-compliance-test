package rule

default rulepass = false

# API: https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunction.html
# Id: 106

rulepass = true{
   input.Configuration.VpcConfig
   input.Configuration.VpcConfig.VpcId
}

#If the VPC network is configured with LAMBDA then test will pass