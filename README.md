# Prancer Compliance test repository

## Introduction
Prancer is a pre-deployment and post-deployment multi-cloud security platform for your Infrastructure as Code (IaC) and live cloud environment. It shifts the security to the left and provides end-to-end security scanning based on the Policy as Code concept. DevOps engineers can use it for static code analysis on IaC to find security drifts and maintain their cloud security posture with continuous compliance features. you can get more information from our website at : https://www.prancer.io

## How to use the repository
The easiest way to get up and running is to make sure you can run the scenario we are explaining in the [Hello World example](https://www.prancer.io/guidance/). after being able to run that simple scenario, you can use this repository to do more advanced security tests.

## Repository structure
The repository consists of 4 high level folders representing each supported type:
 - AWS
 - Azure
 - Google
 - Kubernetes

Under each top level directory, we have `cloud`, `iac` and `terraform` folders which hold the `rego` files respectively.
 - `cloud` folder holds all the rego files related to post deployment tests. These tests contribute to have continuous compliance in the cloud
 - `iac` folder holds all the rego files related to IaC Security Scan. These tests contribute to shift security to left concept
 - `terraform` folder holds all the rego files related to Terraform Infrastructure as Code

## Prerequisites
Make sure you have the following prerequisites available:
 - Linux distribution
 - Python 3.6.8 / 3.8 / 3.9
 - Prancer Basic [How to install prancer basic](https://docs.prancer.io/installation/)
 - OPA [How to install OPA binary](https://www.openpolicyagent.org/docs/latest/#running-opa)
 > Note: We recommend moving `opa` to a directory included in your system's `PATH` (i.e `/usr/local/bin/`)

 ## Sample scenario
 There are lots of use cases available for the [Prancer Platform](https://www.prancer.io/introduction/?section=use-case-scenarios). Here I will show you a sample scenario to IaC Scan Azure ARM template.

 > The complete code is available in the [Hello World](https://github.com/prancer-io/prancer-hello-world) repository

The easiest way is to clone our [Hello World](https://github.com/prancer-io/prancer-hello-world) repository, change the parameters and run it.

### step 1 - Clone the `Hello World` sample repo
`git clone https://github.com/prancer-io/prancer-hello-world`
`cd prancer-hello-world`

### step 2 - Change the connector file to point to your IaC code repo
You can use the available connector and change the `gitProvider` attribute to point to your own repo. (https://github.com/prancer-io/prancer-hello-world/blob/master/gitConnectorArmRemoteStructure.json)

`cat gitConnectorArmRemoteStructure.json`
```
{
    "fileType": "structure",
    "type": "filesystem",
    "companyName": "prancer",
    "gitProvider": "https://github.com/prancer-io/prancer-armof.git",
    "branchName": "master",
    "private": false
}
```

### step 3 - Verify Master snapshot and Master test files
The next step is to verify master snapshot and master test files which are pointed to this repository. The complete code is already available in our `Hello World` sample repository and you don't need to change anything. You can find the sample codes here:
https://github.com/prancer-io/prancer-hello-world/tree/master/validation/scenario-arm-remote

`cat validation/scenario-arm-remote/master-snapshot.json`
```
{
    "$schema": "",
    "contentVersion": "1.0.0.0",
    "fileType": "masterSnapshot",
    "connector": "gitConnectorRemote",
    "remoteFile": "azure/iac/master-snapshot.json",
    "connectorUsers": [
      {
        "id": "USER_1",
        "testUser": "user1",
        "source": "gitConnectorArmRemoteStructure"
      }
    ]
}
```

`cat validation/scenario-arm-remote/master-test.json`
```
{
    "contentVersion": "1.0.0.0",
    "notification": [],
    "masterSnapshot": "master-snapshot",
    "fileType": "mastertest",
    "connector": "gitConnectorRemote",
    "remoteFile": "azure/iac/master-compliance-test.json"
}
```

### step 4 - running the IaC Scan
run the command `prancer --crawler scenario-arm-remote` to get all the files available in your repository. And then `prancer scenario-arm-remote` to complete the IaC security tests for Azure ARM templates.
