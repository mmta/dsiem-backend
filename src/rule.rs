use std::{ net::IpAddr, sync::Arc, collections::HashSet };

use cidr::IpCidr;
use serde::{ Serializer, Deserializer };
use serde_derive::{ Deserialize, Serialize };
use tokio::sync::RwLock;
use tracing::warn;

use crate::{ event::NormalizedEvent, asset::NetworkAssets };
use anyhow::Result;

#[derive(PartialEq, Clone, Debug)]
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

#[derive(Deserialize, Serialize, Clone, Debug)]
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
    #[serde(skip_serializing_if = "is_zero_or_less")]
    #[serde(default)]
    pub start_time: i64,
    #[serde(skip_serializing_if = "is_zero_or_less")]
    #[serde(default)]
    pub end_time: i64,
    #[serde(skip_serializing_if = "is_zero_or_less")]
    #[serde(default)]
    pub rcvd_time: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub status: String,
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
    #[serde(skip_serializing, skip_deserializing)]
    pub sticky_diffdata: Arc<RwLock<StickyDiffData>>,
    #[serde(skip_serializing, skip_deserializing)]
    pub event_ids: Arc<RwLock<HashSet<String>>>,
}

/// This is only used for serialize
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_or_less(num: &i64) -> bool {
    *num <= 0
}
impl Default for DirectiveRule {
    fn default() -> Self {
        DirectiveRule {
            name: "".to_string(),
            stage: 1,
            plugin_id: 0,
            plugin_sid: vec![],
            product: vec![],
            category: "".to_string(),
            subcategory: vec![],
            occurrence: 0,
            from: "".to_string(),
            to: "".to_string(),
            rule_type: RuleType::UnsupportedType,
            port_from: "".to_string(),
            port_to: "".to_string(),
            protocol: "".to_string(),
            reliability: 0,
            timeout: 0,
            start_time: 0,
            end_time: 0,
            rcvd_time: 0,
            status: "".to_string(),
            sticky_different: "".to_string(),
            custom_data1: "".to_string(),
            custom_label1: "".to_string(),
            custom_data2: "".to_string(),
            custom_label2: "".to_string(),
            custom_data3: "".to_string(),
            custom_label3: "".to_string(),
            sticky_diffdata: Arc::new(RwLock::new(StickyDiffData::default())),
            event_ids: Arc::new(RwLock::new(vec![].into_iter().collect())),
        }
    }
}

impl DirectiveRule {
    pub async fn does_event_match(
        &self,
        a: &NetworkAssets,
        e: &NormalizedEvent,
        mut_sdiff: bool
    ) -> bool {
        if self.rule_type == RuleType::PluginRule {
            plugin_rule_check(self, a, e, mut_sdiff).await
        } else if self.rule_type == RuleType::TaxonomyRule {
            taxonomy_rule_check(self, a, e, mut_sdiff).await
        } else {
            false
        }
    }
}

async fn plugin_rule_check(
    r: &DirectiveRule,
    a: &NetworkAssets,
    e: &NormalizedEvent,
    mut_sdiff: bool
) -> bool {
    if e.plugin_id != r.plugin_id {
        return false;
    }
    let mut sid_match = false;
    for v in r.plugin_sid.iter() {
        if *v == e.plugin_sid {
            sid_match = true;
            break;
        }
    }
    if !sid_match {
        return false;
    }
    if r.sticky_different == "PLUGIN_SID" {
        _ = is_int_stickydiff(e.plugin_sid, &r.sticky_diffdata, mut_sdiff);
    }
    ip_port_check(r, a, e, mut_sdiff).await && custom_data_check(r, e, mut_sdiff).await
}

async fn taxonomy_rule_check(
    r: &DirectiveRule,
    a: &NetworkAssets,
    e: &NormalizedEvent,
    mut_sdiff: bool
) -> bool {
    if r.category != e.category {
        return false;
    }
    let mut product_match = false;
    for v in r.product.iter() {
        if *v == e.product {
            product_match = true;
            break;
        }
    }
    if !product_match {
        return false;
    }
    // subcategory is optional and can use "ANY"
    if !r.subcategory.is_empty() {
        let mut sc_match = false;
        for v in r.subcategory.iter() {
            if *v == e.subcategory || *v == "ANY" {
                sc_match = true;
                break;
            }
        }
        if !sc_match {
            return false;
        }
    }
    ip_port_check(r, a, e, mut_sdiff).await
}

async fn custom_data_check(r: &DirectiveRule, e: &NormalizedEvent, mut_sdiff: bool) -> bool {
    let r1 = if !r.custom_data1.is_empty() && r.custom_data1 != "ANY" {
        match_text_case_insensitive(&r.custom_data1, &e.custom_data1) ||
            is_string_match_csvrule(&r.custom_data1, &e.custom_data1)
    } else {
        true
    };
    let r2 = if !r.custom_data2.is_empty() && r.custom_data2 != "ANY" {
        match_text_case_insensitive(&r.custom_data2, &e.custom_data2) ||
            is_string_match_csvrule(&r.custom_data2, &e.custom_data2)
    } else {
        true
    };
    let r3 = if !r.custom_data3.is_empty() && r.custom_data3 != "ANY" {
        match_text_case_insensitive(&r.custom_data3, &e.custom_data3) ||
            is_string_match_csvrule(&r.custom_data3, &e.custom_data3)
    } else {
        true
    };

    match r.sticky_different.as_str() {
        "CUSTOM_DATA1" => {
            _ = is_string_stickydiff(&e.custom_data1, &r.sticky_diffdata, mut_sdiff).await;
        }
        "CUSTOM_DATA2" => {
            _ = is_string_stickydiff(&e.custom_data2, &r.sticky_diffdata, mut_sdiff).await;
        }
        "CUSTOM_DATA3" => {
            _ = is_string_stickydiff(&e.custom_data3, &r.sticky_diffdata, mut_sdiff).await;
        }
        &_ => {}
    }

    r1 && r2 && r3
}

async fn ip_port_check(
    r: &DirectiveRule,
    a: &NetworkAssets,
    e: &NormalizedEvent,
    mut_sdiff: bool
) -> bool {
    let in_homenet = a.is_in_homenet(&e.src_ip);
    if r.from == "HOME_NET" && !in_homenet {
        return false;
    }
    if r.from == "!HOME_NET" && in_homenet {
        return false;
    }
    // covers  r.From == "IP", r.From == "IP1, IP2, !IP3", r.From == CIDR-netaddr, r.From == "CIDR1, CIDR2, !CIDR3"
    if
        r.from != "HOME_NET" &&
        r.from != "!HOME_NET" &&
        r.from != "ANY" &&
        !is_ip_match_csvrule(&r.from, e.src_ip)
    {
        return false;
    }
    if r.from != "ANY" && !is_string_match_csvrule(&r.port_from, &e.src_port.to_string()) {
        return false;
    }
    if r.to != "ANY" && !is_string_match_csvrule(&r.port_to, &e.dst_port.to_string()) {
        return false;
    }

    match r.sticky_different.as_str() {
        "SRC_IP" => {
            _ = is_string_stickydiff(&e.src_ip.to_string(), &r.sticky_diffdata, mut_sdiff).await;
        }
        "DST_IP" => {
            _ = is_string_stickydiff(&e.dst_ip.to_string(), &r.sticky_diffdata, mut_sdiff).await;
        }
        "SRC_PORT" => {
            _ = is_int_stickydiff(e.src_port.into(), &r.sticky_diffdata, mut_sdiff).await;
        }
        "DST_PORT" => {
            _ = is_int_stickydiff(e.dst_port.into(), &r.sticky_diffdata, mut_sdiff).await;
        }
        &_ => {}
    }

    true
}

fn match_text_case_insensitive(rule_string: &str, term: &str) -> bool {
    let mut rule_string = rule_string.to_string();
    let is_inverse = rule_string.starts_with('!');
    if is_inverse {
        rule_string.remove(0);
    }
    let m = rule_string.to_lowercase() == term.to_lowercase();
    if is_inverse {
        return !m;
    }
    m
    // m ^ is_inverse
}
fn is_string_match_csvrule(rules_in_csv: &str, term: &String) -> bool {
    let mut result = false;
    let rules: Vec<String> = rules_in_csv
        .split(',')
        .map(|s| s.to_string())
        .collect();
    for mut v in rules {
        let is_inverse = v.starts_with('!');
        if is_inverse {
            v = v.replace('!', "");
        }
        let term_is_equal = v == *term;

        /*
            The correct logic here is to AND all inverse rules,
            and then OR the result with all the non-inverse rules.
            The following code implement that with shortcuts.
        */

        // break early if !condition is violated
        if is_inverse && term_is_equal {
            result = false;
            break;
        }
        // break early if condition is fulfilled
        if !is_inverse && term_is_equal {
            result = true;
            break;
        }

        // if !condition is fulfilled, continue evaluation of next in item
        if is_inverse && !term_is_equal {
            result = true;
        }
        // !isInverse && !termIsEqual should result in match = false (default)
        // so there's no need to handle it
    }
    result
}

fn is_ip_match_csvrule(rules_in_csv: &str, ip: IpAddr) -> bool {
    let mut result = false;
    let rules: Vec<String> = rules_in_csv
        .split(',')
        .map(|s| s.to_string())
        .collect();
    for mut v in rules {
        let is_inverse = v.starts_with('!');
        if is_inverse {
            v = v.replace('!', "");
        }
        if !v.contains('/') {
            v += "/32";
        }
        let res = v.parse();
        if res.is_err() {
            warn!("cannot parse CIDR {}, make sure the directive is configured correctly", v);
        }
        let ipnet_a: IpCidr = res.unwrap();
        let term_is_equal = ipnet_a.contains(&ip);

        /*
			The correct logic here is to AND all inverse rules,
			and then OR the result with all the non-inverse rules.
			The following code implement that with shortcuts.
		*/

        // break early if !condition is violated
        if is_inverse && term_is_equal {
            result = false;
            break;
        }
        // break early if condition is fulfilled
        if !is_inverse && term_is_equal {
            result = true;
            break;
        }

        // if !condition is fulfilled, continue evaluation of next in item
        if is_inverse && !term_is_equal {
            result = true;
        }
        // !isInverse && !termIsEqual should result in match = false (default)
        // so there's no need to handle it
    }
    result
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct StickyDiffData {
    pub sdiff_string: Vec<String>,
    pub sdiff_int: Vec<u64>,
}

// is_int_stickydiff checks if v fulfill stickydiff condition
async fn is_int_stickydiff(v: u64, s: &Arc<RwLock<StickyDiffData>>, add_new: bool) -> Result<bool> {
    let r_guard = s.read().await;
    for n in r_guard.sdiff_int.iter() {
        if *n == v {
            return Ok(false);
        }
    }
    if add_new {
        let mut w_guard = s.write().await;
        w_guard.sdiff_int.push(v); // add it to the collection
    }
    Ok(true)
}

// is_string_stickydiff checks if v fulfill stickydiff condition
async fn is_string_stickydiff(
    v: &str,
    s: &Arc<RwLock<StickyDiffData>>,
    add_new: bool
) -> Result<bool> {
    let r_guard = s.read().await;
    for s in r_guard.sdiff_string.iter() {
        if *s == v {
            return Ok(false);
        }
    }
    if add_new {
        let mut w_guard = s.write().await;
        w_guard.sdiff_string.push(v.to_string());
    }
    Ok(true)
}

#[derive(Clone, Debug)]
pub struct SIDPair {
    plugin_id: u64,
    plugin_sid: Vec<u64>,
}
#[derive(Clone, Debug)]
pub struct TaxoPair {
    product: Vec<String>,
    category: String,
}

// GetQuickCheckPairs returns SIDPairs and TaxoPairs for a given set of directive rules
pub fn get_quick_check_pairs(rules: &Vec<DirectiveRule>) -> (Vec<SIDPair>, Vec<TaxoPair>) {
    let mut sid_pairs = vec![];
    let mut taxo_pairs = vec![];
    for r in rules {
        if r.plugin_id != 0 && !r.plugin_sid.is_empty() {
            sid_pairs.push(SIDPair {
                plugin_id: r.plugin_id,
                plugin_sid: r.plugin_sid.clone(),
            });
        }
        if !r.product.is_empty() && !r.category.is_empty() {
            taxo_pairs.push(TaxoPair {
                product: r.product.clone(),
                category: r.category.clone(),
            });
        }
    }
    (sid_pairs, taxo_pairs)
}

// QuickCheckTaxoRule checks event against the key fields in a directive taxonomy rules
pub fn quick_check_taxo_rule(pairs: &[TaxoPair], e: &NormalizedEvent) -> bool {
    let last = pairs
        .iter()
        .filter(|v| {
            let v = v.product
                .clone()
                .into_iter()
                .filter(|x| *x == e.product)
                .last();
            v.is_some()
        })
        .filter(|v| { v.category == e.category })
        .last();
    last.is_some()
}

// QuickCheckPluginRule checks event against the key fields in a directive plugin rules
pub fn quick_check_plugin_rule(pairs: &[SIDPair], e: &NormalizedEvent) -> bool {
    let last = pairs
        .iter()
        .filter(|v| v.plugin_id == e.plugin_id)
        .filter(|v| {
            let v = v.plugin_sid
                .clone()
                .into_iter()
                .filter(|x| *x == e.plugin_sid)
                .last();
            v.is_some()
        })
        .last();
    last.is_some()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_quick_check_pairs() {
        let r1 = DirectiveRule {
            plugin_id: 1,
            plugin_sid: vec![1, 2, 3],
            ..Default::default()
        };

        let r2 = DirectiveRule {
            product: vec!["checkpoint".to_string()],
            category: "firewall".to_string(),
            ..Default::default()
        };
        let rules = vec![r1.clone(), r2];
        let (p, q) = get_quick_check_pairs(&rules);
        assert!(!p.is_empty());
        assert!(!q.is_empty());
        let (_, q) = get_quick_check_pairs(&vec![r1]);
        assert!(q.is_empty())
    }
    #[test]
    fn test_quick_check_plugin_rule() {
        let pair = vec![
            SIDPair {
                plugin_id: 1,
                plugin_sid: vec![1, 2, 3],
            },
            SIDPair {
                plugin_id: 2,
                plugin_sid: vec![1, 2, 3],
            }
        ];
        let mut event = NormalizedEvent {
            plugin_id: 1,
            plugin_sid: 1,
            ..Default::default()
        };
        assert!(quick_check_plugin_rule(&pair, &event));
        event.plugin_sid = 4;
        assert!(!quick_check_plugin_rule(&pair, &event));
        event.plugin_id = 3;
        assert!(!quick_check_plugin_rule(&pair, &event))
    }
    #[test]
    fn test_quick_check_taxo_rule() {
        let pair = vec![
            TaxoPair {
                category: "firewall".to_owned(),
                product: vec!["checkpoint".to_owned(), "fortigate".to_owned()],
            },
            TaxoPair {
                category: "waf".to_owned(),
                product: vec!["f5".to_owned(), "modsec".to_owned()],
            }
        ];
        let mut event = NormalizedEvent {
            product: "checkpoint".to_string(),
            category: "firewall".to_string(),
            ..Default::default()
        };
        assert!(quick_check_taxo_rule(&pair, &event));
        event.category = "waf".to_string();
        assert!(!quick_check_taxo_rule(&pair, &event));
        event.product = "pf".to_string();
        assert!(!quick_check_taxo_rule(&pair, &event))
    }
}