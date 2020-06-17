package rule

default rulepass = false

# API: https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html
# Id: 3

rulepass = true{
   	input.SummaryMap.AccountAccessKeysPresent=0
}
