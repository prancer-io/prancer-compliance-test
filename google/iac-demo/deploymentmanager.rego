package rule

# Virtual Machine
virtual_machine {
    resource = input.resources[_]
    resource.type == "compute.v1.instance"
    resource.properties.zone
}

virtual_machine = false {
    resource = input.resources[_]
    resource.type == "compute.v1.instance"
    not resource.properties.zone
}

virtual_machine_error = "Err: Virtual Machine Zone does not set" {
    virtual_machine == false
}

# Virtual Network
virtual_network {
    resource = input.resources[_]
    resource.type == "compute.v1.network"
    resource.properties.autoCreateSubnetworks == true
}

virtual_network = false {
    resource = input.resources[_]
    resource.type == "compute.v1.network"
    resource.properties.autoCreateSubnetworks != true
}

virtual_network_error = "Err: Virtual Network does not enabled autoCreateSubnetworks setting" {
    virtual_network == false
}

# firewall
firewall {
    resource = input.resources[_]
    resource.type == "compute.v1.firewall"
    allowed = resource.properties.allowed[_]
    lower(allowed.IPProtocol) == "tcp"
    allowed.ports[_] == 80
}

firewall = false {
    resource = input.resources[_]
    resource.type == "compute.v1.firewall"
    allowed = resource.properties.allowed[_]
    lower(allowed.IPProtocol) == "tcp"
    allowed.ports[_] != 80
}

firewall_error = "Err: firewall rule does not allowed port 80 for IPProtocol `TCP`" {
    firewall == false
}


# cloud_sql
cloud_sql {
    resource = input.resources[_]
    resource.type == "sqladmin.v1beta4.instance"
    resource.properties.region == "us-central1"
}

cloud_sql = false {
    resource = input.resources[_]
    resource.type == "sqladmin.v1beta4.instance"
    resource.properties.region != "us-central1"
}

cloud_sql_error = "Err: cloud sql region does not set to `us-central1`" {
    cloud_sql == false
}


# dataproc
dataproc {
    resource = input.resources[_]
    resource.type == "dataproc.v1.cluster"
    resource.properties.clusterName
}

dataproc = false {
    resource = input.resources[_]
    resource.type == "dataproc.v1.cluster"
    not resource.properties.clusterName
}

dataproc_error = "Err: dataproc, cluster name does not set" {
    dataproc == false
}


# sqladmin
sqladmin {
    resource = input.resources[_]
    resource.type == "sqladmin.v1beta4.user"
    resource.properties.host
    resource.properties.password
}

sqladmin = false {
    resource = input.resources[_]
    resource.type == "sqladmin.v1beta4.user"
    not resource.properties.host
    not resource.properties.password
}

sqladmin_error = "Err: sqladmin, host and password does not set" {
    sqladmin == false
}