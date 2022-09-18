



# Title: Ensure the Load Balancer Listener SSLPolicy is set to at least one value from approved policies


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ELB-015

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ELB-015|
|eval|data.rule.elb_listener_sslpolicy|
|message|data.rule.elb_listener_sslpolicy_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html|
|remediationFunction|PR_AWS_CFR_ELB_015.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Ensure the Load Balancer Listener SSLPolicy is set to at least one value from approved policies, else an Actor can gain access to ADATUM information due to misconfigured cryptographic settings  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA CCM', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-UEM-06', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.a', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-12.1.2', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018', 'ISO/IEC 27018:2019-12.1.2', 'MAS TRM', 'MAS TRM 2021-7.2.1', 'MAS TRM 2021-7.2.2', 'NIST CSF', 'NIST CSF-PR.IP-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.4.2', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS v3.2.1-6.3', 'PCI-DSS']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::elasticloadbalancingv2::listener']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/elb.rego
