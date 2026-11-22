#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiStability {
    Alpha,
    Beta,
    Stable,
    Deprecated,
}

impl ApiStability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Alpha => "xray:api:alpha",
            Self::Beta => "xray:api:beta",
            Self::Stable => "xray:api:stable",
            Self::Deprecated => "xray:api:deprecated",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Annotation {
    pub api: String,
}

impl Annotation {
    pub fn new(api: impl Into<String>) -> Self {
        Self { api: api.into() }
    }

    pub fn from_stability(stability: ApiStability) -> Self {
        Self {
            api: stability.as_str().to_string(),
        }
    }
}
