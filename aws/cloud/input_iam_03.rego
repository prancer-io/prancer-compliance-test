#
# PR-AWS-0084
#

package rule

default rulepass = false

rulepass = true{
	["arn:aws:iam::aws:policy/AmazonElasticTranscoderFullAccess" | input.AttachedPolicies[_].PolicyArn]
}
