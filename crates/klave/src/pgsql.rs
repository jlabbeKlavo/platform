//! Environment definitions for compiling Klave Trustless Applications.
//! LLM module for Klave SDK
use crate::sdk;

pub fn connection_open(uri: &str) -> Result<String, Box<dyn std::error::Error>> {
    match sdk::connection_open(uri) {
        Ok(opaque_handle) => Ok(opaque_handle),
        Err(err) => Err(err.into()),
    }
}

pub fn query(connection: &str, query: &str) -> Result<String, Box<dyn std::error::Error>> {
    //Remove all leading and trailing whitespace from the query and consecutive whitespaces and carriage returns
    let query = query.trim().replace("\n", " ").replace("\r", " ").split_whitespace().collect::<Vec<&str>>().join(" ");    
    if query.is_empty() {
        return Err("Query cannot be empty".into());
    }
    match sdk::sql_query(connection, &query) {
        Ok(result) => Ok(result),
        Err(err) => Err(err.into()),
    }
}

pub fn execute(connection: &str, query: &str) -> Result<String, Box<dyn std::error::Error>> {
    //Remove all leading and trailing whitespace from the query and consecutive whitespaces and carriage returns
    let query = query.trim().replace("\n", " ").replace("\r", " ").split_whitespace().collect::<Vec<&str>>().join(" ");    
    if query.is_empty() {
        return Err("Query cannot be empty".into());
    }
    match sdk::sql_exec(connection, &query) {
        Ok(result) => Ok(result),
        Err(err) => Err(err.into()),
    }
}
