#
# PR-AWS-0033
#

package rule

default rulepass = false

rulepass = true{
    input.ConfigurationRecorders[_].recordingGroup.allSupported=true
    input.ConfigurationRecorders[_].recordingGroup.includeGlobalResourceTypes=true
}
