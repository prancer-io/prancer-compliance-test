#
# PR-AWS-0072
#

package rule

default rulepass = true

# API : https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html

rulepass = false {
	  input.LoadBalancerAttributes.AccessLog.Enabled == false
}
