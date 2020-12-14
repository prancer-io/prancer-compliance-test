#
# PR-AWS-0106
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunction.html

rulepass {
   input.Configuration.VpcConfig
   input.Configuration.VpcConfig.VpcId
}

#If the VPC network is configured with LAMBDA then test will pass
