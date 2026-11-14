/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
*/

/// MSAL Runtime `ResponseStatus` values (mirrors WAM / libmsalruntime).
const STATUS_UNEXPECTED: u32 = 0;
const STATUS_INTERACTION_REQUIRED: u32 = 2;
const STATUS_API_CONTRACT_VIOLATION: u32 = 6;
const STATUS_INCORRECT_CONFIGURATION: u32 = 9;

/// Numeric tags observed in libmsalruntime broker error output.
const TAG_UNEXPECTED: u32 = 508_117_271;
const TAG_INTERACTION_REQUIRED: u32 = 557_973_645;

pub fn broker_error_object(context: &str) -> serde_json::Value {
    let (status, tag, sub_status) = classify_broker_error(context);
    serde_json::json!({
        "context": context,
        "status": status,
        "subStatus": sub_status,
        "tag": tag,
    })
}

fn classify_broker_error(context: &str) -> (u32, u32, u32) {
    let ctx = context.to_ascii_lowercase();

    if ctx.contains("invalid request for user")
        || ctx.contains("invalid redirecturi")
        || ctx.contains("missing account")
    {
        return (STATUS_API_CONTRACT_VIOLATION, TAG_UNEXPECTED, 0);
    }

    if ctx.contains("aadsts50076")
        || ctx.contains("aadsts50158")
        || ctx.contains("interaction_required")
        || ctx.contains("consent_required")
    {
        return (STATUS_INTERACTION_REQUIRED, TAG_INTERACTION_REQUIRED, 0);
    }

    if ctx.contains("aadsts70007") || ctx.contains("aadsts50011") {
        return (STATUS_INCORRECT_CONFIGURATION, TAG_UNEXPECTED, 0);
    }

    if ctx.contains("aadsts") {
        return (STATUS_INTERACTION_REQUIRED, TAG_INTERACTION_REQUIRED, 0);
    }

    if ctx.contains("unable to find account") || ctx.contains("unable to load account") {
        return (STATUS_INTERACTION_REQUIRED, TAG_INTERACTION_REQUIRED, 0);
    }

    if ctx.contains("failed to authenticate user") {
        return (STATUS_INTERACTION_REQUIRED, TAG_INTERACTION_REQUIRED, 0);
    }

    (STATUS_UNEXPECTED, TAG_UNEXPECTED, 0)
}

#[cfg(test)]
mod tests {
    use super::broker_error_object;

    #[test]
    fn token_errors_include_tag() {
        let obj = broker_error_object("Failed to authenticate user");
        assert_eq!(obj["tag"], 557_973_645);
        assert_eq!(obj["status"], 2);
    }

    #[test]
    fn contract_violation_is_not_interaction_required() {
        let obj = broker_error_object("Invalid request for user!");
        assert_eq!(obj["status"], 6);
        assert_eq!(obj["tag"], 508_117_271);
    }

    #[test]
    fn aadsts70007_is_incorrect_configuration() {
        let obj = broker_error_object(
            "GeneralFailure(\"AADSTS70007: The application requested an unsupported mode ''\")",
        );
        assert_eq!(obj["status"], 9);
    }
}
