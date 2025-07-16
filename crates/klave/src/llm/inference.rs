//! Environment definitions for compiling Klave Trustless Applications.
//! LLM module for Klave SDK
use crate::{llm::secret_llama_idl_v1::AggregateRule, sdk};

pub fn compute(input: &str, input_tensor: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match sdk::inference_compute(input, input_tensor) {
        Ok(result) => Ok(result),
        Err(err) => Err(err.into()),
    }
}

pub fn add_prompt(context_name: &str, prompt: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    match sdk::inference_add_prompt(context_name, prompt) {
        Ok(_) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

pub fn get_piece(context_name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match sdk::inference_get_piece(context_name) {
        Ok(result) => Ok(result),
        Err(err) => Err(err.into()),
    }
}

pub fn get_pieces(context_name: &str, nb_pieces: i32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match sdk::inference_get_pieces(context_name, nb_pieces) {
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
