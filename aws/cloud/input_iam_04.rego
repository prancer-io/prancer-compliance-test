#
# PR-AWS-0096
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAttachedUserPolicies.html

rulepass = true{
	is_array(input.AttachedPolicies)=true
	count(input.AttachedPolicies)>1
}
