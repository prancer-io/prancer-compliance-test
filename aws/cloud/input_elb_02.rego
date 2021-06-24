#
# PR-AWS-0065
#

package rule

default rulepass = false

# API : https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html

rulepass = true {
    # lower(input.json.Type) == "aws::elasticloadbalancing::loadbalancer"
    input.json.LoadBalancerAttributes.ConnectionDraining.Enabled=true
}

metadata := {
    "Policy Code": "PR-AWS-0065",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Elastic Load Balancer (Classic) with connection draining disabled",
    "Policy Description": "This policy identifies Classic Elastic Load Balancers which have connection draining disabled. Connection Draining feature ensures that a Classic load balancer stops sending requests to instances that are de-registering or unhealthy, while keeping the existing connections open. This enables the load balancer to complete in-flight requests made to instances that are de-registering or unhealthy.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html"
}

# If the connection draining enabled for load balancer then test will pass