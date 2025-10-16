//! Environment definitions for compiling Klave Trustless Applications.
//! LLM module for Klave SDK
use crate::{llm::secret_llama_idl_v1::AggregateRule, sdk};
use serde_json;

pub fn add_prompt(context_name: &str, user_prompt: &str) -> Result<(), Box<dyn std::error::Error>> {
    match sdk::inference_add_prompt(context_name, user_prompt) {
        Ok(_) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

pub fn add_frame(context_name: &str, user_prompt: &str, frame_bytes_b64: &str) -> Result<(), Box<dyn std::error::Error>> {
    match sdk::inference_add_frame(context_name, user_prompt, frame_bytes_b64) {
        Ok(_) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

pub fn get_piece(context_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    match sdk::inference_get_piece(context_name) {
        Ok(result) => Ok(result),
        Err(err) => Err(err.into()),
    }
}

pub fn get_pieces(context_name: &str, nb_pieces: i32) -> Result<String, Box<dyn std::error::Error>> {
    match sdk::inference_get_pieces(context_name, nb_pieces) {
        Ok(result) => Ok(result),
        Err(err) => Err(err.into()),
    }
}

pub fn get_messages(context_name: &str, role: i32) -> Result<String, Box<dyn std::error::Error>> {
    match sdk::inference_get_messages(context_name, role) {
        Ok(result) => Ok(result),
        Err(err) => Err(err.into()),
    }
}

pub fn get_parameters(context_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    match sdk::inference_get_parameters(context_name) {
        Ok(result) => Ok(result),
        Err(err) => Err(err.into()),
    }
}

pub fn model_n_embd(context_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    match sdk::inference_model_n_embd(context_name) {
        Ok(result) => Ok(result),
        Err(err) => Err(err.into()),
    }
}

pub fn bytes_to_f32_vector(bytes: &[u8]) -> Result<Vec<f32>, Box<dyn std::error::Error>> {
    if bytes.len() % 4 != 0 {
        return Err("Byte array length must be divisible by 4 for f32 conversion".into());
    }

    let floats = bytes
        .chunks_exact(4)
        .map(|chunk| {
            let array: [u8; 4] = chunk.try_into().unwrap();
            f32::from_le_bytes(array)
        })
        .collect();

    Ok(floats)
}

pub fn f32_vector_to_bytes(floats: &[f32]) -> Vec<u8> {
    floats
        .iter()
        .flat_map(|f| f.to_le_bytes())
        .collect()
}

pub fn get_aggregate_embeddings(context_name: &str, window_size: i32, agg_rule: AggregateRule) -> Result<Vec<f32>, Box<dyn std::error::Error>> {

    match sdk::inference_get_aggregate_embeddings(context_name, window_size, agg_rule as i32) {
        Ok(result) => bytes_to_f32_vector(&result),
        Err(err) => Err(err.into()),
    }
}

pub fn get_embeddings(context_name: &str, user_prompt: Vec<&str>) -> Result<Vec<Vec<f32>>, Box<dyn std::error::Error>> {
    match sdk::inference_get_embeddings(context_name, &serde_json::to_string(&user_prompt)
            .map_err(|e| format!("Failed to serialize user prompt: {}", e))? ) {
        Ok(result) => {
            let embeddings: Vec<Vec<f32>> = serde_json::from_str(&result)
                .map_err(|e| format!("Failed to parse embeddings JSON: {}", e))?;
            Ok(embeddings)
        },
        Err(err) => Err(err.into()),
    }
}

pub fn bytes_to_i32_vector(bytes: &[u8]) -> Result<Vec<i32>, Box<dyn std::error::Error>> {
    if bytes.len() % 4 != 0 {
        return Err("Byte array length must be divisible by 4 for i32 conversion".into());
    }

    let integers = bytes
        .chunks_exact(4)
        .map(|chunk| {
            let array: [u8; 4] = chunk.try_into().unwrap();
            i32::from_le_bytes(array)
        })
        .collect();

    Ok(integers)
}

pub fn i32_vector_to_bytes(integers: &[i32]) -> Vec<u8> {
    integers
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect()
}

pub fn encode(context_name: &str, prompt: &[u8]) -> Result<Vec<i32>, Box<dyn std::error::Error>> {
    match sdk::inference_encode(context_name, prompt) {
        Ok(result) => bytes_to_i32_vector(&result),
        Err(err) => Err(err.into()),
    }
}

pub fn decode(context_name: &str, token_ids: &[i32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match sdk::inference_decode(context_name, &i32_vector_to_bytes(&token_ids)) {
        Ok(result) => Ok(result),
        Err(err) => Err(err.into()),
    }
}

pub fn ingest(context_name: &str, token_ids: &[i32]) -> Result<(), Box<dyn std::error::Error>> {
    match sdk::inference_ingest(context_name, &i32_vector_to_bytes(&token_ids)) {
        Ok(_) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

// Tool management functions
pub fn add_tool(context_name: &str, name: &str, description: &str, parameters_schema: &str) -> Result<(), Box<dyn std::error::Error>> {
    match sdk::inference_add_tool(context_name, name, description, parameters_schema) {
        Ok(_) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

pub fn remove_tool(context_name: &str, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    match sdk::inference_remove_tool(context_name, name) {
        Ok(_) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

pub fn clear_tools(context_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    match sdk::inference_clear_tools(context_name) {
        Ok(_) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

pub fn list_tools(context_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    match sdk::inference_list_tools(context_name) {
        Ok(result) => Ok(result),
        Err(err) => Err(err.into()),
    }
}

pub fn set_tool_choice(context_name: &str, choice_type: &str, function_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    match sdk::inference_set_tool_choice(context_name, choice_type, function_name) {
        Ok(_) => Ok(()),
        Err(err) => Err(err.into()),
    }
}