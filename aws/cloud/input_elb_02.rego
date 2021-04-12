#
# PR-AWS-0065
#

package rule

default rulepass = false

# API : https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html

rulepass = true {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    input.LoadBalancerAttributes.ConnectionDraining.Enabled=true
}

# If the connection draining enabled for load balancer then test will pass