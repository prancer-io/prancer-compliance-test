#
# PR-AWS-0003
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html

rulepass = true {
    lower(input.Type) == "aws::iam::policy"
    input.SummaryMap.AccountAccessKeysPresent=0
}
