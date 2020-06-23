package rule

default rulepass = false

# API: https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunction.html
# Id: 107

rulepass = true {
   input.Configuration.TracingConfig.Mode!="PassThrough"
}

#If the active tracing is enabled with LAMBDA then test will pass