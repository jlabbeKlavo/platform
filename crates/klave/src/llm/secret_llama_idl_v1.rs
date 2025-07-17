//! Environment definitions for compiling Klave Trustless Applications.
//! LLM module for Klave SDK

use serde::{Deserialize, Serialize};
use serde_json::Value;

// Assuming these are defined in your wasi_nn_idl_v1 module
use crate::llm::wasi_nn_idl_v1::TensorType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(into = "u8", try_from = "&str")]
pub enum EncryptionType {
    None = 0,
    AesGcm = 1,
    AesCtr = 2,
    AesEcb = 3,
}

impl From<EncryptionType> for u8 {
    fn from(encryption_type: EncryptionType) -> Self {
        encryption_type as u8
    }
}

impl TryFrom<&str> for EncryptionType {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "None" => Ok(EncryptionType::None),
            "AesGcm" => Ok(EncryptionType::AesGcm),
            "AesCtr" => Ok(EncryptionType::AesCtr),
            "AesEcb" => Ok(EncryptionType::AesEcb),
            _ => Err(format!("Unknown encryption type: {}", value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(into = "u8", try_from = "&str")]
pub enum EngineType {
    Llama2c = 0, // Llama2c engine
    SgxLlamaCpp = 1, // LlamaCpp sgx engine
    TdxLlamaCpp = 2, // LlamaCpp tdx engine
    HostLlamaCpp = 3, // LlamaCpp host engine
    BitNet = 4, // BitNet engine
}

impl From<EngineType> for u8 {
    fn from(engine_type: EngineType) -> Self {
        engine_type as u8
    }
}

impl TryFrom<&str> for EngineType {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Llama2c" => Ok(EngineType::Llama2c),
            "SgxLlamaCpp" => Ok(EngineType::SgxLlamaCpp),
            "TdxLlamaCpp" => Ok(EngineType::TdxLlamaCpp),
            "HostLlamaCpp" => Ok(EngineType::HostLlamaCpp),
            "BitNet" => Ok(EngineType::BitNet),
            _ => Err(format!("Unknown engine type: {}", value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(into = "u8", try_from = "&str")]
pub enum Access {
    Public = 0,      // Public access
    Private = 1,     // Private access
    Restricted = 2,  // Restricted access
    Internal = 3,    // Internal use only
    Confidential = 4, // Confidential data
}

impl From<Access> for u8 {
    fn from(access: Access) -> Self {
        access as u8
    }
}

impl TryFrom<&str> for Access {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Public" => Ok(Access::Public),
            "Private" => Ok(Access::Private),
            "Restricted" => Ok(Access::Restricted),
            "Internal" => Ok(Access::Internal),
            "Confidential" => Ok(Access::Confidential),
            _ => Err(format!("Unknown access type: {}", value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(into = "u8", try_from = "&str")]
pub enum HashType {
    None = 0,
    Sha1 = 1,
    Sha2256 = 2,
    Sha2384 = 3,
    Sha2512 = 4,
    Sha3256 = 5,
    Sha3384 = 6,
    Sha3512 = 7,
    Md5 = 8,
    Cmac128 = 11,
}

impl From<HashType> for u8 {
    fn from(hash_type: HashType) -> Self {
        hash_type as u8
    }
}

impl TryFrom<&str> for HashType {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "None" => Ok(HashType::None),
            "Sha1" => Ok(HashType::Sha1),
            "Sha2256" => Ok(HashType::Sha2256),
            "Sha2384" => Ok(HashType::Sha2384),
            "Sha2512" => Ok(HashType::Sha2512),
            "Sha3256" => Ok(HashType::Sha3256),
            "Sha3384" => Ok(HashType::Sha3384),
            "Sha3512" => Ok(HashType::Sha3512),
            "Md5" => Ok(HashType::Md5),
            "Cmac128" => Ok(HashType::Cmac128),
            _ => Err(format!("Unknown hash type: {}", value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(into = "u8", try_from = "&str")]
pub enum ModelFormat {
    Openvino = 0,
    Onnx = 1,
    Tensorflow = 2,
    Pytorch = 3,
    TensorflowLite = 4,
    Ggml = 5,
    Gguf = 6,
    Llama2 = 7,
    PaddlePaddle = 8,  
    Caffe = 9,
    Mxnet = 10,
    Autodetect = 127, // Automatically detect the model format
}

impl From<ModelFormat> for u8 {
    fn from(model_format: ModelFormat) -> Self {
        model_format as u8
    }
}

impl TryFrom<&str> for ModelFormat {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Openvino" => Ok(ModelFormat::Openvino),
            "Onnx" => Ok(ModelFormat::Onnx),
            "Tensorflow" => Ok(ModelFormat::Tensorflow),
            "Pytorch" => Ok(ModelFormat::Pytorch),
            "TensorflowLite" => Ok(ModelFormat::TensorflowLite),
            "Ggml" => Ok(ModelFormat::Ggml),
            "Gguf" => Ok(ModelFormat::Gguf),
            "Llama2" => Ok(ModelFormat::Llama2),
            "PaddlePaddle" => Ok(ModelFormat::PaddlePaddle),
            "Caffe" => Ok(ModelFormat::Caffe),
            "Mxnet" => Ok(ModelFormat::Mxnet),
            "Autodetect" => Ok(ModelFormat::Autodetect),
            _ => Err(format!("Unknown model format: {}", value)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDescription {
    pub brief: String, // e.g. "A large language model for text generation";
    pub task: String, // e.g. "text-generation", "text-embedding", "image-generation"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Model {
    pub name: String,
    pub local_path: String,
    pub url: String,
    pub description: ModelDescription,
    pub engine_type: EngineType,
    pub engine_config: Value,
    pub encryption_type: EncryptionType,
    pub encryption_key: Vec<u8>,
    pub hash_type: HashType,
    pub hash: Vec<u8>,
    pub is_loaded: bool,
    pub access: Access,
    pub inactivity_timeout: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tokenizer {
    pub name: String,
    pub local_path: String,
    pub url: String,
    pub description: String,
    pub model_format: ModelFormat, // The model this tokenizer is associated with
    pub engine_type: EngineType,
    pub tensor_type: TensorType,
    pub encryption_type: EncryptionType,
    pub encryption_key: Vec<u8>,
    pub hash_type: HashType,
    pub hash: Vec<u8>,
    pub is_loaded: bool,
    pub access: Access,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphInitContext {
    pub model_name: String,
    pub context_name: String,
    pub system_prompt: String,
    pub temperature: f32,  // 0.0 = greedy deterministic. 1.0 = original. don't set higher
    pub topp: f32,         // top-p in nucleus sampling. 1.0 = off. 0.9 works well, but slower
    pub steps: i32,        // number of steps to run for
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceIteration {
    pub piece: Vec<u8>,
    pub complete: bool,
}

pub enum AggregateRule {
    None,
    Average,
    Maximum,
    Minimum,
    Median,
    Any,
    First,
    Last,
}