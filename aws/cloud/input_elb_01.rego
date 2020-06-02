package rule

default rulepass = false

rulepass = true{
   input.LoadBalancerAttributes.AccessLog.Enabled=true
}

# If the access logs enabled for load balancer then test will pass