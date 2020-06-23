package rule

default rulepass = false

# API: https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeCluster.html
# Id: 54

rulepass = true{
   	input.cluster.logging.clusterLogging[_].enabled=true
}
