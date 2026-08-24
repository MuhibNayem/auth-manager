package authz

default allow := false

# Sensitive actions require MFA
allow {
    input.mfa_verified == true
    input.action in ["transfer_funds", "change_email", "reset_password", "delete_account"]
}

# Non-sensitive actions don't require MFA
allow {
    input.mfa_verified == false
    not input.action in ["transfer_funds", "change_email", "reset_password", "delete_account"]
}
