#
# PR-AWS-0073
#

package rule

default rulepass = true

# API : https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html

rulepass = false {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    lbs := input.LoadBalancerDescriptions[_]
    listeners := lbs.ListenerDescriptions[_]
    not listeners.Listener.SSLCertificateId
}

rulepass = false {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    lbs := input.LoadBalancerDescriptions[_]
    listeners := lbs.ListenerDescriptions[_]
    not startswith(listeners.Listener.SSLCertificateId, "arn:")
}

metadata := {
    "Policy Code": "PR-AWS-0073",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Elastic Load Balancer with listener TLS/SSL disabled",
    "Policy Description": "This policy identifies Elastic Load Balancers which have listener TLS/SSL disabled. As Load Balancers will be handling all incoming requests and routing the traffic accordingly; The listeners on the load balancers should always receive traffic over secure channel with a valid SSL certificate configured.",
    "Compliance": ["CSA-CCM","GDPR","HITRUST","ISO 27001","NIST 800","SOC 2"],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html"
}
