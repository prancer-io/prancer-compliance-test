#
# PR-AWS-0096
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAttachedUserPolicies.html

rulepass = true {
    # lower(input.Type) == "aws::iam::policy"
    is_array(input.AttachedPolicies)=true
    count(input.AttachedPolicies)>1
}

metadata := {
    "Policy Code": "PR-AWS-0096",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS IAM policy attached to users",
    "Policy Description": "This policy identifies IAM policies attached to user.By default, IAM users, groups, and roles have no access to AWS resources. IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended that IAM policies be applied directly to groups and roles but not users.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAttachedUserPolicies.html"
}
