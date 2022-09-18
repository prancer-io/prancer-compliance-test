



# Title: Ensure only private access for Amazon EKS cluster's Kubernetes API is enabled.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-EKS-008

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([eks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-EKS-008|
|eval|data.rule.eks_with_private_access|
|message|data.rule.eks_with_private_access_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_EKS_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy checks if the EKS cluster has public access which can be accessed over the internet.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 26', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 45", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.1.004', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:01.c', 'HITRUST v.9.4.2-Control Reference:09.m', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.5', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1190 - Exploit Public-Facing Application', 'MITRE ATT&CK v6.3-T1190', 'MITRE ATT&CK v8.2-T1190', 'MLPS', 'MLPS 2.0-8.1.3.2', 'NIST 800', 'NIST 800-53 Rev 5-Boundary Protection', 'NIST 800-53 Rev4-SC-7', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.22', 'NIST SP 800-172-3.14.3e', 'PCI DSS v3.2.1-1.3', 'PCI DSS v3.2.1-7.1', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.1.4', 'RMiT', 'Risk Management in Technology (RMiT)-10.55']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::eks::cluster']


[eks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/eks.rego
