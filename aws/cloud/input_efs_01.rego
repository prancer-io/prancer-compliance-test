package rule

default rulepass = false

rulepass = true{
	input.FileSystems[_].Encrypted!=false
}
