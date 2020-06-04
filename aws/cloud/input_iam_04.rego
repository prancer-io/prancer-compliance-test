package rule

default rulepass = false


rulepass = true{
	is_array(input.AttachedPolicies)=true
	count(input.AttachedPolicies)>1
}
