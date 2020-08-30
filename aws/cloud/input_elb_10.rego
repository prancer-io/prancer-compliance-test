package rule

default rulepass = true

# API : https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html
# Id: 73

rulepass = false {
   lbs := input.LoadBalancerDescriptions[_]
   listeners := lbs.ListenerDescriptions[_]
   not listeners.Listener.SSLCertificateId
}

rulepass = false {
   lbs := input.LoadBalancerDescriptions[_]
   listeners := lbs.ListenerDescriptions[_]
   not startswith(listeners.Listener.SSLCertificateId, "arn:")
}
