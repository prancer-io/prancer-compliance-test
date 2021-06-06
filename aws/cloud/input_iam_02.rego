#
# PR-AWS-0082
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountPasswordPolicy.html

rulepass = true {
    lower(input.Type) == "aws::iam::policy"
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

rulepass_metadata := {
    "Policy Code": "PR-AWS-0082",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS IAM Password policy is unsecure",
    "Policy Description": "Checks to ensure that IAM password policy is in place for the cloud accounts. As a security best practice, customers must have strong password policies in place. This policy ensures password policies are set with all following options:_x005F_x000D_ - Minimum Password Length_x005F_x000D_ - At least one Uppercase letter_x005F_x000D_ - At least one Lowercase letter_x005F_x000D_ - At least one Number_x005F_x000D_ - At least one Symbol/non-alphanumeric character_x005F_x000D_ - Users have permission to change their own password_x005F_x000D_ - Password expiration period_x005F_x000D_ - Password reuse_x005F_x000D_ - Password expiration requires administrator reset",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountPasswordPolicy.html"
}
