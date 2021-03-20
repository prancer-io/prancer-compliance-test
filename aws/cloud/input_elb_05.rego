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
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
   policy := input.PolicyDescriptions[_]
   policydescrib := policy.PolicyAttributeDescriptions[_]
   lower(policydescrib.AttributeName) == lower(insecure_ssl_protocol[_])
   policydescrib.AttributeValue == "true"
}
