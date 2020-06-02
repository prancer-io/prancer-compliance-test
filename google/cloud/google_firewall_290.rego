package rule
default rulepass = true

# Firewall rules allow inbound traffic from anywhere with no target tags set
# If Firewall rules not allow inbound traffic from anywhere with no target tags set
# API and Response Reference : https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list
rulepass = false {                                      
   count(notargettags) > 0
}

# 'direction equals "INGRESS" and targetTags[*] does not exist and disabled equals false 
notargettags["NO_TARGET_TAGS"] {
   input.direction="INGRESS"
   input.disabled= false 
   not input.targetTags
}
# 'direction equals "INGRESS" and targetServiceAccounts[*] does not exist' and disabled equals false 
notargettags["NO_TARGET_TAGSSERVICEACCOUNT"] {
   input.direction= "INGRESS"
   input.disabled= false 
   not input.targetServiceAccounts
}