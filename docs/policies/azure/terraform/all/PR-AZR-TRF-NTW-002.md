



# Master Test ID: PR-AZR-TRF-NTW-002


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([networkwatchersflowlogs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-NTW-002|
|eval|data.rule.netwatch_logs|
|message|data.rule.netwatch_logs_err|
|remediationDescription|In 'azurerm_network_watcher_flow_log' resource, set 'enabled = true' under 'traffic_analytics' block to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_watcher_flow_log#enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_NTW_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Azure Network Watcher Network Security Group (NSG) traffic analytics should be enabled

***<font color="white">Description:</font>*** This policy identifies Azure Network Security Groups (NSG) for which flow logs are disabled. To perform this check, enable this action on the Azure Service Principal: 'Microsoft.Network/networkWatchers/queryFlowLogStatus/action'.<br><br>NSG flow logs, a feature of the Network Watcher app, enable you to view information about ingress and egress IP traffic through an NSG. The flow logs include information such as:<br>- Outbound and inbound flows on a per-rule basis.<br>- Network interface to which the flow applies.<br>- 5-tuple information about the flow (source/destination IP, source/destination port, protocol).<br>- Whether the traffic was allowed or denied.<br><br>As a best practice, enable NSG flow logs to improve network visibility.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_network_watcher_flow_log']


[networkwatchersflowlogs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/networkwatchersflowlogs.rego
