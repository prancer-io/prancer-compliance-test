package rule

default rulepass = false

rulepass = true{
   input.LoadBalancerAttributes.CrossZoneLoadBalancing.Enabled=true
}

# If the cross zone load balancing enabled for load balancer then test will pass