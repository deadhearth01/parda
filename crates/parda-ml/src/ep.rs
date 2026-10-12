//! Hardware acceleration selection for ONNX Runtime.

use std::str::FromStr;

use ort::execution_providers::ExecutionProviderDispatch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionProvider {
    /// The best provider compiled into this build, falling back to CPU.
    Auto,
    Cpu,
    CoreMl,
    DirectMl,
    Cuda,
}

impl FromStr for ExecutionProvider {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "auto" | "" => ExecutionProvider::Auto,
            "cpu" => ExecutionProvider::Cpu,
            "coreml" => ExecutionProvider::CoreMl,
            "directml" => ExecutionProvider::DirectMl,
            "cuda" => ExecutionProvider::Cuda,
            other => anyhow::bail!("unknown execution provider `{other}`"),
        })
    }
}

impl ExecutionProvider {
    /// ONNX Runtime providers to register, in preference order. ONNX Runtime
    /// falls back to CPU for any operator a provider cannot run.
    pub fn dispatch(self) -> Vec<ExecutionProviderDispatch> {
        #[allow(unused_mut)]
        let mut v: Vec<ExecutionProviderDispatch> = Vec::new();
        let want = |p: ExecutionProvider| self == p || self == ExecutionProvider::Auto;
        #[cfg(feature = "cuda")]
        if want(ExecutionProvider::Cuda) {
            v.push(ort::execution_providers::CUDAExecutionProvider::default().build());
        }
        #[cfg(feature = "directml")]
        if want(ExecutionProvider::DirectMl) {
            v.push(ort::execution_providers::DirectMLExecutionProvider::default().build());
        }
        #[cfg(feature = "coreml")]
        if want(ExecutionProvider::CoreMl) {
            v.push(ort::execution_providers::CoreMLExecutionProvider::default().build());
        }
        let _ = want;
        v
    }

    pub fn label(self) -> &'static str {
        match self {
            ExecutionProvider::Auto => "auto",
            ExecutionProvider::Cpu => "cpu",
            ExecutionProvider::CoreMl => "coreml",
            ExecutionProvider::DirectMl => "directml",
            ExecutionProvider::Cuda => "cuda",
        }
    }
}
