output "connection_to_servers" {
  value = "Connect using Session Manager"
}


output "tfe_appplication" {
  value = "https://${var.dns_hostname}.${var.dns_zonename}"
}

# output "ssh_tfe_server" {
#   value = "ssh ${local.os_user}@${var.dns_hostname}.${var.dns_zonename}"
# }

# output "ssh_tfe_server_ip" {
#   value = "ssh ${local.os_user}@${aws_eip.tfe-eip.public_ip}"
# }

# output "ssh_tf_client" {
#   value = "ssh ${local.os_user}@${var.dns_hostname}-client.${var.dns_zonename}"
# }

# output "full_chain" {
#   value = "${acme_certificate.certificate.certificate_pem}${acme_certificate.certificate.issuer_pem}"
# }