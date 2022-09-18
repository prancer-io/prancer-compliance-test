



# Title: GCP VM instances have serial port access enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-INST-003

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-INST-003|
|eval|data.rule.vm_serial_port|
|message|data.rule.vm_serial_port_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_INST_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies VM instances which have serial port access enabled. Interacting with a serial port is often referred to as the serial console. The interactive serial console does not support IP-based access restrictions such as IP whitelists. If you enable the interactive serial console on an instance, clients can attempt to connect to that instance from any IP address. So it is recommended to keep interactive serial console support disabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'CIS']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['compute.v1.instance']


[compute.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/compute.rego
