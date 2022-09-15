



# Master Test ID: PR-AWS-CLD-IAM-030


***<font color="white">Master Snapshot Id:</font>*** ['TEST_IAM_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-IAM-030|
|eval|data.rule.elasticsearch_iam_policy_not_overly_permissive_to_all_traffic|
|message|data.rule.elasticsearch_iam_policy_not_overly_permissive_to_all_traffic_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_policy_versions' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_IAM_030.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Ensure IAM policy is not overly permissive to all traffic for elasticsearch.

***<font color="white">Description:</font>*** It identifies Elasticsearch IAM policies that are overly permissive to all traffic. Amazon Elasticsearch service makes it easy to deploy and manage Elasticsearch. Customers can create a domain where the service is accessible. The domain should be granted access restrictions so that only authorized users and applications have access to the service.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Well-Architected Framework', 'AWS Well-Architected Framework-Identity and Access Management', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-DSI-02', 'CSA CCM v3.0.1-IAM-07', 'CSA CCM v3.0.1-IVS-06', 'CSA CCM v3.0.1-IVS-08', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 21", "CyberSecurity Law of the People's Republic of China-Article 25", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.183', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SI.2.216', 'GDPR', 'GDPR-Article 32', 'GDPR-Article 46', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:09.ab', 'HITRUST v.9.4.2-Control Reference:01.n', 'HITRUST v.9.4.2-Control Reference:01.o', 'LGPD', 'MAS TRM', 'MAS TRM 2021-9.1.1', 'MITRE ATT&CK', 'MITRE ATT&CK v6.3-T1098', 'MLPS', 'MLPS 2.0-8.1.3.2', 'NIST 800', 'NIST 800-171 Rev1-3.13.1', 'NIST 800-171 Rev1-3.13.2', 'NIST 800-171 Rev1-3.13.5', 'NIST 800-171 Rev1-3.14.6', 'NIST 800-53 Rev 5-Boundary Protection \| Block Communication from Non-organizationally Configured Hosts', 'NIST 800-53 Rev 5-System Monitoring \| Inbound and Outbound Communications Traffic', 'NIST 800-53 Rev4-SC-7 (19)', 'NIST 800-53 Rev4-SI-4 (4)', 'NIST CSF', 'NIST CSF-DE.AE-1', 'NIST CSF-PR.AC-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.6', 'NIST SP 800-171 Revision 2-3.14.6', 'NIST SP 800-172-3.14.2e', 'PCI DSS v3.2.1-1.2.1', 'PCI-DSS', 'RMiT', 'Risk Management in Technology (RMiT)-10.55', 'Risk Management in Technology (RMiT)-10.68', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC6.6', 'SOC 2-CC6.7']|
|service|['iam']|



[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
