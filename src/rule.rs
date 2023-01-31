use serde::{ Serializer, Deserializer };
use serde_derive::{ Deserialize, Serialize };

#[derive(PartialEq, Clone)]
pub enum RuleType {
    PluginRule,
    TaxonomyRule,
    UnsupportedType,
}

impl serde::Serialize for RuleType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_str(match *self {
            RuleType::PluginRule => "PluginRule",
            RuleType::TaxonomyRule => "TaxonomyRule",
            RuleType::UnsupportedType => "",
        })
    }
}

impl<'de> serde::Deserialize<'de> for RuleType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "PluginRule" => RuleType::PluginRule,
            "TaxonomyRule" => RuleType::TaxonomyRule,
            &_ => RuleType::UnsupportedType,
        })
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct DirectiveRule {
    pub name: String,
    pub stage: u8,
    pub plugin_id: u64,
    pub plugin_sid: Vec<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub product: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub category: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub subcategory: Vec<String>,
    pub occurrence: u64,
    pub from: String,
    pub to: String,
    #[serde(rename(deserialize = "type"))]
    pub rule_type: RuleType,
    pub port_from: String,
    pub port_to: String,
    pub protocol: String,
    pub reliability: u8,
    pub timeout: u64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(default)]
    pub start_time: u64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(default)]
    pub end_time: u64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(default)]
    pub rcvd_time: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub sticky_different: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub custom_data1: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub custom_label1: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub custom_data2: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub custom_label2: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub custom_data3: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub custom_label3: String,
}

/// This is only used for serialize
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(num: &u64) -> bool {
    *num == 0
}

#[derive(Deserialize, Default, Clone)]
pub struct StickyDiffData {
    pub sdiff_string: Vec<String>,
    pub sdiff_int: Vec<u64>,
}