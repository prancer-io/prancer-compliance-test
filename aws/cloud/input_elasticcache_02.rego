package rule

default rulepass = false

rulepass = true{
  input.ReplicationGroups[_].AuthTokenEnabled=true
  input.ReplicationGroups[_].TransitEncryptionEnabled=true
}
