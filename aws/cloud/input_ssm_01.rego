package rule

default rulepass = false


rulepass = true{
    input.Parameters[_].Type='SecureString'
}
