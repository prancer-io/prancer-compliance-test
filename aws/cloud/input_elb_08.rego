package rule

default rulepass = true

# API : https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html
# Id: 69

rulepass = false {
    count(input.LoadBalancerDescriptions[_].Instances) == 0
}

rulepass = false {
    lbdescrib = input.LoadBalancerDescriptions[_]
    not lbdescrib.Instances
}
