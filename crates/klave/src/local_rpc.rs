use crate::sdk;

// If call_service is defined in sdk.rs, ensure it is public:
// pub fn call_service(...) { ... }
// Otherwise, import it directly if it's in another module:
// use crate::sdk::call_service;

pub fn local_rpc_query(service_name: &str, function: &str, args: &str) -> Result<String, Box<dyn std::error::Error>> {
    match sdk::call_service(service_name, function, args) {
        Ok(result) => Ok(result),
        Err(err) => Err(err.into()),
    }
}
