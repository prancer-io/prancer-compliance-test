#
# PR-AWS-0063
#

package rule

default rulepass = true

# API : https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html

insecure_ssl_protocol := [
    "Protocol-SSLv3",
    "Protocol-TLSv1",
    "Protocol-TLSv1.1"
]

rulepass = false {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    policy := input.PolicyDescriptions[_]
    policydescrib := policy.PolicyAttributeDescriptions[_]
    lower(policydescrib.AttributeName) == lower(insecure_ssl_protocol[_])
    policydescrib.AttributeValue == "true"
}

metadata := {
    "Policy Code": "PR-AWS-0063",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with vulnerable SSL protocol",
    "Policy Description": "This policy identifies Elastic Load Balancers (Classic) which are configured with SSL negotiation policy containing vulnerable SSL protocol. The SSL protocol establishes a secure connection between a client and a server and ensures that all the data passed between the client and your load balancer is private. As a security best practice, it is recommended to use the latest version SSL protocol.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html"
}
