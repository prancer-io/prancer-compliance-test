#
# PR-AWS-0072
#

package rule

default rulepass = true

# API : https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html

rulepass = false {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    input.LoadBalancerAttributes.AccessLog.Enabled == false
}

rulepass_metadata := {
    "Policy Code": "PR-AWS-0072",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Elastic Load Balancer v2 (ELBv2) Application Load Balancer (ALB) with access log disabled",
    "Policy Description": "This policy identifies ELBv2 ALBs which have access log disabled. Access logs capture detailed information about requests sent to your load balancer and each log contains information such as the time the request was received, the client's IP address, latencies, request paths, and server responses. You can use these access logs to analyze traffic patterns and troubleshoot issues.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerAttributes.html"
}
