#
# PR-AWS-0069
#

package rule

default rulepass = true

# API : https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html

rulepass = false {
    # lower(input.json.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(input.json.LoadBalancerDescriptions[_].Instances) == 0
}

rulepass = false {
    lbdescrib = input.json.LoadBalancerDescriptions[_]
    not lbdescrib.Instances
}

metadata := {
    "Policy Code": "PR-AWS-0069",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Elastic Load Balancer (ELB) not in use",
    "Policy Description": "This policy identifies unused Elastic Load Balancers (ELBs) in your AWS account. Any Elastic Load Balancer in your AWS account is adding charges to your monthly bill, although it is not used by any resources. As a best practice, it is recommended to remove ELBs that are not associated with any instances, it will also help you avoid unexpected charges on your bill.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html"
}
