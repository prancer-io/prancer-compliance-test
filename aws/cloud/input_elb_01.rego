#
# PR-AWS-0064
#

package rule

default rulepass = false

# API : https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html

rulepass = true{
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
   input.LoadBalancerAttributes.AccessLog.Enabled=true
}

# If the access logs enabled for load balancer then test will pass