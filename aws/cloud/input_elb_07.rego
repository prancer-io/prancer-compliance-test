#
# PR-AWS-0068
#

package rule

default rulepass = true

# API : https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html

rulepass = false {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(input.LoadBalancerDescriptions[_].SecurityGroups) == 0
}

rulepass_metadata := {
    "Policy Code": "PR-AWS-0068",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Elastic Load Balancer (ELB) has security group with no outbound rules",
    "Policy Description": "This policy identifies Elastic Load Balancers (ELB) which have security group with no outbound rules. A security group with no outbound rule will deny all outgoing requests. ELB security groups should have at least one outbound rule, ELB with no outbound permissions will deny all traffic going to any EC2 instances or resources configured behind that ELB; in other words, the ELB is useless without outbound permissions.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html"
}

# false if there none security groups associate with ELB
