package rule

disk {
    resource = input.resources[_]
    lower(resource.type) == "compute.v1.disk"
    resource.properties.zone
    resource.properties.zone != null
    resource.properties.zone != ""
}

disk = false {
    resource = input.resources[_]
    lower(resource.type) == "compute.v1.disk"
    not resource.type
}

disk_err = "zone is not set in disk" {
    disk == false
}
