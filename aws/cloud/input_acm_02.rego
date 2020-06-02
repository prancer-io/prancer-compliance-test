package rule

default rulepass = false


rulepass = true{
	count(input.Certificate.InUseBy)>0
}
