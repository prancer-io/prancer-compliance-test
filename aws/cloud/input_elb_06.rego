package rule

default rulepass = true

# API : https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html
# Id: 67

rulepass = false {
    count(input.LoadBalancerDescriptions[_].SecurityGroups) == 0
}

# false if there none security groups associate with ELB
