



# Title: Azure Network Security Group (NSG) should not allow traffic from internet on port 3389


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-NSG-015

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([nsg.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-NSG-015|
|eval|data.rule.inbound_port_3389|
|message|data.rule.inbound_port_3389_err|
|remediationDescription|Make sure you are following the ARM template guidelines for NSG by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups' target='_blank'>here</a>|
|remediationFunction|PR_AZR_ARM_NSG_015.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Blocking RDP port 3389 will protect users from attacks like account compromise, Denial of service and ransomware.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-NS-1', 'Azure Security Benchmark (v3)-GS-9', 'Azure Security Benchmark (v3)-NS-1', 'Azure Security Benchmark (v3)-NS-2', 'Azure Security Benchmark (v3)-NS-3', 'Azure Security Benchmark (v3)-NS-7', 'Azure Security Benchmark (v3)-NS-8', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-6.1', 'CIS v1.2.0 (Azure)-6.1', 'CIS v1.3.0 (Azure)-6.1', 'CIS v1.3.1 (Azure)-6.1', 'CIS v1.4.0 (Azure)-6.1', 'CSA CCM', 'CSA CCM v3.0.1-DSI-02', 'CSA CCM v3.0.1-IAM-07', 'CSA CCM v3.0.1-IVS-06', 'CSA CCM v3.0.1-IVS-08', "CyberSecurity Law of the People's Republic of China-Article 21", "CyberSecurity Law of the People's Republic of China-Article 25", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.183', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SI.2.216', 'GDPR', 'GDPR-Article 32', 'GDPR-Article 46', 'HIPAA', 'HIPAA-164.312(e)(2)(i)', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:09.ab', 'MITRE ATT&CK', 'MITRE ATT&CK v6.3-T1190', 'MITRE ATT&CK v8.2-T1190', 'MPAA Content Protection Best Practices', 'MPAA Content Protection Best Practices-DS-1.2', 'MPAA Content Protection Best Practices-DS-3.0', 'NIST 800', 'NIST 800-53 Rev4-SC-7 (19)', 'NIST 800-53 Rev4-SI-4 (4)', 'NIST CSF', 'NIST CSF-DE.AE-1', 'NIST CSF-DE.CM-7', 'NIST CSF-PR.AC-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.6', 'NIST SP 800-171 Revision 2-3.14.6', 'NIST SP 800-172-3.14.2e', 'PCI DSS', 'PCI DSS v3.2.1-1.2.1', 'PIPEDA', 'PIPEDA-4.7.3', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC6.6', 'SOC 2-CC6.7']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.network/networksecuritygroups']


[nsg.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/nsg.rego
