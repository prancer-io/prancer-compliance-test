#
# PR-AWS-0003
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html

rulepass = true {
    # lower(input.Type) == "aws::iam::policy"
    input.SummaryMap.AccountAccessKeysPresent=0
}

metadata := {
    "Policy Code": "PR-AWS-0003",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Access key enabled on root account",
    "Policy Description": "This policy identifies root accounts for which access keys are enabled. Access keys are used to sign API requests to AWS. Root accounts have complete access to all your AWS services. If the access key for a root account is compromised, an unauthorized users will have complete access to your AWS account.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html"
}
