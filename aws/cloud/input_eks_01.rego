package rule

default rulepass = false

# API: https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeCluster.html
# Id: 51

rulepass = true{
   	input.cluster.resourcesVpcConfig.endpointPrivateAccess=true
    input.cluster.resourcesVpcConfig.endpointPublicAccess=false
}