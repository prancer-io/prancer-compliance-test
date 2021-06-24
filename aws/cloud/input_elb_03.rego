#
# PR-AWS-0066
#

package rule

default rulepass = false

# API : https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html

rulepass = true {
    # lower(input.json.Type) == "aws::elasticloadbalancing::loadbalancer"
    input.json.LoadBalancerAttributes.CrossZoneLoadBalancing.Enabled=true
}

metadata := {
    "Policy Code": "PR-AWS-0066",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Elastic Load Balancer (Classic) with cross-zone load balancing disabled",
    "Policy Description": "This policy identifies Classic Elastic Load Balancers which have cross-zone load balancing disabled. When Cross-zone load balancing enabled, classic load balancer distributes requests evenly across the registered instances in all enabled Availability Zones. Cross-zone load balancing reduces the need to maintain equivalent numbers of instances in each enabled Availability Zone, and improves your application's ability to handle the loss of one or more instances.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html"
}

# If the cross zone load balancing enabled for load balancer then test will pass