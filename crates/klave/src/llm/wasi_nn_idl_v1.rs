//! Environment definitions for compiling Klave Trustless Applications.
//! WASI NN module for Klave SDK

use serde::{Deserialize, Serialize};
use crate::llm::secret_llama_idl_v1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoadStatus {
    LoadedInRam,
    UnloadedFromRam,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(into = "u8", try_from = "&str")]
pub enum TensorType {
    Fp16 = 0,
    Fp32 = 1,
    Fp64 = 2,
    Bf16 = 3,
    U8 = 4,
    I32 = 5,
    I64 = 6,
}

impl From<TensorType> for u8 {
    fn from(tensor_type: TensorType) -> Self {
        tensor_type as u8
    }
}

impl TryFrom<&str> for TensorType {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Fp16" => Ok(TensorType::Fp16),
            "Fp32" => Ok(TensorType::Fp32),
            "Fp64" => Ok(TensorType::Fp64),
            "Bf16" => Ok(TensorType::Bf16),
            "U8" => Ok(TensorType::U8),
            "I32" => Ok(TensorType::I32),
            "I64" => Ok(TensorType::I64),
            _ => Err(format!("Unknown tensor type: {}", value)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tensor {
    pub dimensions: Vec<u32>,
    pub tensor_type: TensorType,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum GraphEncoding {
    Openvino = 0,
    Onnx = 1,
    Tensorflow = 2,
    Pytorch = 3,
    TensorflowLite = 4,
    Ggml = 5,
    Llama2 = 6,
    PaddlePaddle = 7,
    Caffe = 8,
    Mxnet = 9,
    Autodetect = 127,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedTensor {
    pub name: String,
    pub tensor: Tensor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ExecutionTarget {
    Cpu = 0,
    Gpu = 1,
    Tpu = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphLoadBuilder {
    pub model: secret_llama_idl_v1::Model,
    pub tokenizer: secret_llama_idl_v1::Tokenizer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphLoadInput {
    pub builder: GraphLoadBuilder,
    pub encoding: GraphEncoding,
    pub target: ExecutionTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphInitExecutionContextInput {
    pub metadata: String,
}