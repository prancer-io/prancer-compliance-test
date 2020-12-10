#
# PR-AWS-0054
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeCluster.html

rulepass = true{
   	input.cluster.logging.clusterLogging[_].enabled=true
}
