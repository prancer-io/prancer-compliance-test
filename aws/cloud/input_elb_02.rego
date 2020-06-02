package rule

default rulepass = false

rulepass = true{
   input.LoadBalancerAttributes.ConnectionDraining.Enabled=true
}

# If the connection draining enabled for load balancer then test will pass