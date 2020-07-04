package rule

default rulepass = true

# API: https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunction.html
# Id: 108

rulepass = false {
   to_number(input.Configuration.CodeSize) > 67500000
}
