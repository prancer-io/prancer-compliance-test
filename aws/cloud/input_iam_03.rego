#
# PR-AWS-0084
#

package rule

default rulepass = false

rulepass = true {
    lower(input.Type) == "aws::iam::policy"
    ["arn:aws:iam::aws:policy/AmazonElasticTranscoderFullAccess" | input.AttachedPolicies[_].PolicyArn]
}

metadata := {
    "Policy Code": "PR-AWS-0084",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS IAM deprecated managed policies in use by User",
    "Policy Description": "This policy checks for any usage of deprecated AWS IAM managed policies and returns an alert if it finds one in your cloud resources._x005F_x000D_ _x005F_x000D_ When AWS deprecate an IAM managed policy, a new alternative is released with improved access restrictions. Existing IAM users and roles can continue to use the previous policy without interruption, however new IAM users and roles will use the new replacement policy._x005F_x000D_ _x005F_x000D_ Before you migrate any user or role to the new replacement policy, we recommend you review their differences in the Policy section of AWS IAM console. If you require one or more of the removed permissions, please add them separately to any user or role._x005F_x000D_ _x005F_x000D_ List of deprecated AWS IAM managed policies:_x005F_x000D_ _x005F_x000D_ AmazonElasticTranscoderFullAccess (replaced by AmazonElasticTranscoder_FullAccess)",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
