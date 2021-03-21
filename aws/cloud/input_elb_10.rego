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
