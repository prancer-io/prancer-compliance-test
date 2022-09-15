



# Master Test ID: PR-AWS-CLD-SG-012


***<font color="white">Master Snapshot Id:</font>*** ['TEST_SG']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitygroup.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-SG-012|
|eval|data.rule.port_3389|
|message|data.rule.port_3389_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_SG_012.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** AWS Security Groups allow internet traffic from internet to RDP port (3389)

***<font color="white">Description:</font>*** This policy identifies the security groups which is exposing RDP port (3389) to the internet. Security Groups do not allow inbound traffic on RDP port (3389) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Secure network configuration', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.2.0 (AWS)-4.2', 'CIS v1.3.0 (AWS)-5.2', 'CIS v1.4.0 (AWS)-5.2', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-DSI-02', 'CSA CCM v3.0.1-IAM-07', 'CSA CCM v3.0.1-IVS-06', 'CSA CCM v3.0.1-IVS-08', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 21", "CyberSecurity Law of the People's Republic of China-Article 25", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.183', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SI.2.216', 'GDPR', 'GDPR-Article 32', 'GDPR-Article 46', 'HIPAA', 'HIPAA-164.312(e)(1)', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:09.ab', 'HITRUST v.9.4.2-Control Reference:01.n', 'HITRUST v.9.4.2-Control Reference:01.o', 'ISO 27001', 'ISO 27001:2013-A.13.1.1', 'ISO 27001:2013-A.14.1.2', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.2.4 ', 'MAS TRM 2021-11.2.5', 'MITRE ATT&CK', 'MITRE ATT&CK v6.3-T1108', 'MITRE ATT&CK v6.3-T1190', 'MITRE ATT&CK v8.2-T1190', 'MLPS', 'MLPS 2.0-8.1.3.2', 'MPAA Content Protection Best Practices', 'MPAA Content Protection Best Practices-DS-1.2', 'MPAA Content Protection Best Practices-DS-3.0', 'NIST 800', 'NIST 800-171 Rev1-3.13.1', 'NIST 800-171 Rev1-3.13.2', 'NIST 800-171 Rev1-3.13.5', 'NIST 800-171 Rev1-3.14.6', 'NIST 800-53 Rev 5-Boundary Protection \| Block Communication from Non-organizationally Configured Hosts', 'NIST 800-53 Rev 5-System Monitoring \| Inbound and Outbound Communications Traffic', 'NIST 800-53 Rev4-SC-7 (19)', 'NIST 800-53 Rev4-SI-4 (4)', 'NIST CSF', 'NIST CSF-DE.AE-1', 'NIST CSF-DE.CM-7', 'NIST CSF-PR.AC-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.6', 'NIST SP 800-171 Revision 2-3.14.6', 'NIST SP 800-172-3.14.2e', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-18.1', 'PCI DSS v3.2.1-1.2.1', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.7.3', 'RMiT', 'Risk Management in Technology (RMiT)-10.55', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC6.6']|
|service|['security group']|



[securitygroup.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/securitygroup.rego
