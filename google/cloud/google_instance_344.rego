package rule
default rulepass = false

# enableFlowLogs is false or enableFlowLogs does not exist'

rulepass = true {                                      
   count(enableFlowLogs) >= 2
}

# nodePools[*].config.serviceAccount contains default
enableFlowLogs["input.enableFlowLogs"] {
   input.enableFlowLogs = "false"

}

enableFlowLogs["input.enableFlowLogs"] {
   not input.enableFlowLogs 
}
