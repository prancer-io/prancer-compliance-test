#
# PR-AWS-0082
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountPasswordPolicy.html

rulepass = true{
    lower(resource.Type) == "aws::iam::policy"
    input.PasswordPolicy.RequireNumbers=true
    input.PasswordPolicy.RequireSymbols=true
    input.PasswordPolicy.ExpirePasswords=true
    input.PasswordPolicy.AllowUsersToChangePassword=true
    input.PasswordPolicy.RequireLowercaseCharacters=true
    input.PasswordPolicy.RequireUppercaseCharacters=true
    input.PasswordPolicy.MaxPasswordAge
    input.PasswordPolicy.PasswordReusePrevention
    input.PasswordPolicy.MinimumPasswordLength
}
