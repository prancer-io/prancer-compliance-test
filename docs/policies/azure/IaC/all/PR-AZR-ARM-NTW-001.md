



# Title: Azure Network Watcher Network Security Group (NSG) flow logs should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-NTW-001

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([networkwatchersflowlogs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-NTW-001|
|eval|data.rule.netwatchFlowlogs|
|message|data.rule.netwatchFlowlogs_err|
|remediationDescription|In Resource of type "Microsoft.network/networkwatchers/flowlogs" make sure properties.enabled exists and value is set to true.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networkwatchers/flowlogs' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_NTW_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Azure Network Security Groups (NSG) for which flow logs are disabled. To perform this check, enable this action on the Azure Service Principal: 'Microsoft.Network/networkWatchers/queryFlowLogStatus/action'.<br><br>NSG flow logs, a feature of the Network Watcher app, enable you to view information about ingress and egress IP traffic through an NSG. The flow logs include information such as:<br>- Outbound and inbound flows on a per-rule basis.<br>- Network interface to which the flow applies.<br>- 5-tuple information about the flow (source/destination IP, source/destination port, protocol).<br>- Whether the traffic was allowed or denied.<br><br>As a best practice, enable NSG flow logs to improve network visibility.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CSA CCM', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-06', 'CSA CCM v.4.0.1-LOG-08', 'CSA CCM v.4.0.1-LOG-13', "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:09.ab', 'HITRUST v.9.4.2-Control Reference:09.ac', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.4.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.4.4', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.4.1', 'ISO/IEC 27017:2015-12.4.4', 'ISO/IEC 27017:2015-16.1.2', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1562.008 - Impair Defenses:Disable Cloud Logs', 'NIST 800', 'NIST 800-53 Rev 5-Boundary Protection \| External Telecommunications Services', 'NIST 800-53 Rev 5-System Monitoring \| Analyze Communications Traffic Anomalies', 'NIST 800-53 Rev 5-System Monitoring \| Analyze Traffic and Event Patterns', 'NIST 800-53 Rev 5-System Monitoring \| System-wide Intrusion Detection System', 'NIST 800-53 Rev4-SC-7 (4)(b)', 'NIST 800-53 Rev4-SI-4 (1)', 'NIST 800-53 Rev4-SI-4 (11)', 'NIST 800-53 Rev4-SI-4 (13)', 'NIST CSF', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.14.2e', 'PCI DSS', 'PCI DSS v3.2.1-10.2.3', 'PCI DSS v3.2.1-10.6', 'PIPEDA', 'PIPEDA-4.1.4']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.network/networkwatchers/flowlogs']


[networkwatchersflowlogs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/networkwatchersflowlogs.rego
