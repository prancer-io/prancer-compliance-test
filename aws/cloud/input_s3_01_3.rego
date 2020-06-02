package rule

default rulepass = false

rulepass = true{
   grant := input.Grants[_]
   not contains(grant.Grantee.URI, "AllUsers")
}