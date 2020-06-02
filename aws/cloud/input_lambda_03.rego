package rule

default rulepass = false

rulepass = true {
   input.Configuration.TracingConfig.Mode!="PassThrough"
}

#If the active tracing is enabled with LAMBDA then test will pass