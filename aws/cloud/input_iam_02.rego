package rule

default rulepass = false


rulepass = true{
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
