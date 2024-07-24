locals {
  az1                    = "${var.region}a"
  az2                    = "${var.region}b"
  tags = {
    "OwnedBy" = "patrick.munne@hashicorp.com"
  }
  os_user = var.tfe_os == "ubuntu" ? var.tfe_os : "ec2-user"
}