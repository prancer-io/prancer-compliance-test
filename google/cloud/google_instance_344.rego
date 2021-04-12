#
# PR-GCP-0074
#

package rule
default rulepass = false

# enableFlowLogs is false or enableFlowLogs does not exist'

rulepass = true {
    lower(input.type) == "compute.v1.instance"
    count(enableFlowLogs) >= 2
}

# nodePools[*].config.serviceAccount contains default
enableFlowLogs["input.enableFlowLogs"] {
    input.enableFlowLogs = "false"

}

enableFlowLogs["input.enableFlowLogs"] {
    not input.enableFlowLogs
}
