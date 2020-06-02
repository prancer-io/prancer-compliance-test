package rule

default rulepass = false

rulepass = true{
  input.ReplicationGroups[_].AutomaticFailover="enabled"
}
