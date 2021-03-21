#
# PR-AWS-0084
#

package rule

default rulepass = false

rulepass = true {
    lower(input.Type) == "aws::iam::policy"
    ["arn:aws:iam::aws:policy/AmazonElasticTranscoderFullAccess" | input.AttachedPolicies[_].PolicyArn]
}
