



# Title: AWS SageMaker notebook instance configured with direct internet access feature


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-SGM-003

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sagemaker.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-SGM-003|
|eval|data.rule.sagemaker_direct_internet_access_enabled|
|message|data.rule.sagemaker_direct_internet_access_enabled_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sagemaker-notebookinstance.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_SGM_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies SageMaker notebook instances that are configured with direct internet access feature. If AWS SageMaker notebook instances are configured with direct internet access feature, any machine outside the VPC can establish a connection to these instances, which provides an additional avenue for unauthorized access to data and the opportunity for malicious activity.

For more details:
https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.1.004', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:01.c', 'HITRUST v.9.4.2-Control Reference:09.m', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.2.1', 'MAS TRM 2021-7.2.2', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1190 - Exploit Public-Facing Application', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.22', 'NIST SP 800-172-3.14.3e', 'PCI DSS v3.2.1-1.3', 'PCI DSS v3.2.1-7.1', 'PCI-DSS', 'RMiT', 'Risk Management in Technology (RMiT)-10.55']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::sagemaker::notebookinstance']


[sagemaker.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sagemaker.rego
