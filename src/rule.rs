use std::{ net::IpAddr, sync::Arc, collections::HashSet };

use cidr::IpCidr;
use serde::{ Serializer, Deserializer };
use serde_derive::{ Deserialize, Serialize };
use parking_lot::RwLock;
use tracing::{ warn, error };

use crate::{ event::NormalizedEvent, asset::NetworkAssets };
use anyhow::Result;

#[derive(PartialEq, Clone, Debug, Default)]
pub enum RuleType {
    PluginRule,
    TaxonomyRule,
    #[default]
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

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
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
    pub occurrence: usize,
    pub from: String,
    pub to: String,
    #[serde(rename(deserialize = "type"))]
    pub rule_type: RuleType,
    pub port_from: String,
    pub port_to: String,
    pub protocol: String,
    pub reliability: u8,
    pub timeout: u32,
    #[serde(skip_serializing_if = "is_locked_zero_or_less")]
    #[serde(default)]
    pub start_time: Arc<RwLock<i64>>,
    #[serde(skip_serializing_if = "is_locked_zero_or_less")]
    #[serde(default)]
    pub end_time: Arc<RwLock<i64>>,
    #[serde(skip_serializing_if = "is_locked_string_empty")]
    #[serde(default)]
    pub status: Arc<RwLock<String>>,
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

// This is only used for serialize
fn is_locked_zero_or_less(num: &Arc<RwLock<i64>>) -> bool {
    let r = num.read();
    *r <= 0
}
// This is only used for serialize
fn is_locked_string_empty(s: &Arc<RwLock<String>>) -> bool {
    let r = s.read();
    r.is_empty()
}

impl DirectiveRule {
    pub fn does_event_match(
        &self,
        a: &NetworkAssets,
        e: &NormalizedEvent,
        mut_sdiff: bool
    ) -> bool {
        if self.rule_type == RuleType::PluginRule {
            plugin_rule_check(self, a, e, mut_sdiff)
        } else if self.rule_type == RuleType::TaxonomyRule {
            taxonomy_rule_check(self, a, e, mut_sdiff)
        } else {
            false
        }
    }

    pub fn reset_arc_fields(mut self) -> Self {
        self.start_time = Default::default();
        self.end_time = Default::default();
        self.status = Default::default();
        self.sticky_diffdata = Default::default();
        self.event_ids = Default::default();
        self
    }
}

fn plugin_rule_check(
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
        error!("returning 3");
        return false;
    }
    if r.sticky_different == "PLUGIN_SID" {
        _ = is_int_stickydiff(e.plugin_sid, &r.sticky_diffdata, mut_sdiff);
    }
    ip_port_check(r, a, e, mut_sdiff) && custom_data_check(r, e, mut_sdiff)
}

fn taxonomy_rule_check(
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
    ip_port_check(r, a, e, mut_sdiff)
}

fn custom_data_check(r: &DirectiveRule, e: &NormalizedEvent, mut_sdiff: bool) -> bool {
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
            _ = is_string_stickydiff(&e.custom_data1, &r.sticky_diffdata, mut_sdiff);
        }
        "CUSTOM_DATA2" => {
            _ = is_string_stickydiff(&e.custom_data2, &r.sticky_diffdata, mut_sdiff);
        }
        "CUSTOM_DATA3" => {
            _ = is_string_stickydiff(&e.custom_data3, &r.sticky_diffdata, mut_sdiff);
        }
        &_ => {}
    }

    r1 && r2 && r3
}

fn ip_port_check(
    r: &DirectiveRule,
    a: &NetworkAssets,
    e: &NormalizedEvent,
    mut_sdiff: bool
) -> bool {
    let srcip_in_homenet = a.is_in_homenet(&e.src_ip);
    if r.from == "HOME_NET" && !srcip_in_homenet {
        return false;
    }
    if r.from == "!HOME_NET" && srcip_in_homenet {
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

    let dst_ip_in_homenet = a.is_in_homenet(&e.dst_ip);
    if r.to == "HOME_NET" && !srcip_in_homenet {
        return false;
    }
    if r.to == "!HOME_NET" && dst_ip_in_homenet {
        return false;
    }
    // covers  r.From == "IP", r.From == "IP1, IP2, !IP3", r.From == CIDR-netaddr, r.From == "CIDR1, CIDR2, !CIDR3"
    if
        r.to != "HOME_NET" &&
        r.to != "!HOME_NET" &&
        r.to != "ANY" &&
        !is_ip_match_csvrule(&r.to, e.dst_ip)
    {
        return false;
    }

    if r.port_from != "ANY" && !is_string_match_csvrule(&r.port_from, &e.src_port.to_string()) {
        return false;
    }
    if r.port_to != "ANY" && !is_string_match_csvrule(&r.port_to, &e.dst_port.to_string()) {
        return false;
    }

    match r.sticky_different.as_str() {
        "SRC_IP" => {
            _ = is_string_stickydiff(&e.src_ip.to_string(), &r.sticky_diffdata, mut_sdiff);
        }
        "DST_IP" => {
            _ = is_string_stickydiff(&e.dst_ip.to_string(), &r.sticky_diffdata, mut_sdiff);
        }
        "SRC_PORT" => {
            _ = is_int_stickydiff(e.src_port.into(), &r.sticky_diffdata, mut_sdiff);
        }
        "DST_PORT" => {
            _ = is_int_stickydiff(e.dst_port.into(), &r.sticky_diffdata, mut_sdiff);
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
        v = v.trim().to_owned();
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
        .map(|s| s.trim().to_string())
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
            warn!(
                "cannot parse CIDR {}: {:?}. make sure the directive is configured correctly",
                v,
                res.unwrap_err()
            );
            continue;
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
fn is_int_stickydiff(v: u64, s: &Arc<RwLock<StickyDiffData>>, add_new: bool) -> Result<bool> {
    let r_guard = s.read();
    for n in r_guard.sdiff_int.iter() {
        if *n == v {
            return Ok(false);
        }
    }
    if add_new {
        let mut w_guard = s.write();
        w_guard.sdiff_int.push(v); // add it to the collection
    }
    Ok(true)
}

// is_string_stickydiff checks if v fulfill stickydiff condition
fn is_string_stickydiff(v: &str, s: &Arc<RwLock<StickyDiffData>>, add_new: bool) -> Result<bool> {
    let r_guard = s.read();
    for s in r_guard.sdiff_string.iter() {
        if *s == v {
            return Ok(false);
        }
    }
    if add_new {
        let mut w_guard = s.write();
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
    use std::str::FromStr;

    use super::*;
    use table_test::table_test;

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
        let v = p
            .into_iter()
            .filter(|v| v.plugin_id == 1 && v.plugin_sid == vec![1, 2, 3])
            .last();
        assert!(v.is_some());
        let v = q
            .into_iter()
            .filter(|v| v.product == vec!["checkpoint"] && v.category == "firewall")
            .last();
        assert!(v.is_some());
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
            product: "checkpoint".to_owned(),
            category: "firewall".to_owned(),
            ..Default::default()
        };
        assert!(quick_check_taxo_rule(&pair, &event));
        event.category = "waf".to_string();
        assert!(!quick_check_taxo_rule(&pair, &event));
        event.product = "pf".to_string();
        assert!(!quick_check_taxo_rule(&pair, &event))
    }

    #[test]
    fn test_netaddr_in_csv() {
        let table = vec![
            (("192.168.0.1", "192.168.0.0/16"), true),
            (("192.168.0.1", "192.168.0.1"), true),
            (("192.168.0.1", "192.168.0.1/32"), true),
            (("192.168.0.1", "192.168.0.1/24"), false),
            (("192.168.0.1", "!10.0.0.0/16"), true),
            (("192.168.0.1", "!10.0.0.0/16, 192.168.0.0/24"), true),
            (("192.168.0.1", "!192.168.0.0/24"), false),
            (("192.168.0.1", "10.0.0.0/16, !192.168.0.0/16"), false),
            (("192.168.0.1", "10.0.0.0/16, !192.168.0.0/16, 192.168.0.0/16"), false)
        ];

        for (validator, (input_1, input_2), expected) in table_test!(table) {
            let ip = input_1.parse::<IpAddr>().unwrap();
            let actual = is_ip_match_csvrule(input_2, ip);

            validator
                .given(&format!("rules: {}, term: {}", input_2, input_1))
                .when("is_ip_match_csvrule")
                .then(&format!("it should be {}", expected))
                .assert_eq(expected, actual);
        }
    }

    #[test]
    fn test_term_in_csv() {
        let table = vec![
            (("1231", "1000, 1001"), false),
            (("1231", "!1231, 1001"), false),
            (("1231", "1000, !1231"), false),
            (("1231", "1231, !1231"), true),
            (("1231", "!1231, 1231"), false),
            (("1231", "!1000, !1001"), true),
            (("1231", "!1000, 1001"), true),
            (("1231", "1001, !1000"), true),
            (("1231", "!1000, 1231"), true),
            (("foo", "!bar, foobar, foo"), true)
        ];

        for (validator, (input_1, input_2), expected) in table_test!(table) {
            let actual = is_string_match_csvrule(input_2, &input_1.to_owned());

            validator
                .given(&format!("rules: {}, term: {}", input_2, input_1))
                .when("is_string_match_csvrule")
                .then(&format!("it should be {}", expected))
                .assert_eq(expected, actual);
        }
    }

    #[test]
    fn test_plugin_rule() {
        let asset_string =
            r#"{
            "assets": [
              {
                "name": "Firewall",
                "cidr": "192.168.0.1/32",
                "value": 5
              },
              {
                "name": "VulnerabilityScanner",
                "cidr": "192.168.0.2/32",
                "value": 5,
                "whitelisted": true
              },
              {
                "name": "192-168-Net",
                "cidr": "192.168.0.0/16",
                "value": 2
              },
              {
                "name": "10-Net",
                "cidr": "10.0.0.0/8",
                "value": 2
              },
              {
                "name": "172-16-Net",
                "cidr": "172.16.0.0/12",
                "value": 2
              }
            ]  
          }
          "#;
        let a = NetworkAssets::from_str(asset_string.to_owned()).unwrap();

        let r1 = DirectiveRule {
            rule_type: RuleType::PluginRule,
            plugin_id: 1001,
            plugin_sid: vec![50001],
            product: vec!["IDS".to_string()],
            category: "Malware".to_string(),
            subcategory: vec!["C&C Communication".to_string()],
            from: "HOME_NET".to_string(),
            to: "ANY".to_string(),
            port_from: "ANY".to_string(),
            port_to: "ANY".to_string(),
            protocol: "ANY".to_string(),
            ..Default::default()
        };
        let e1 = NormalizedEvent {
            plugin_id: 1001,
            plugin_sid: 50001,
            product: "IDS".to_string(),
            category: "Malware".to_string(),
            subcategory: "C&C Communication".to_string(),
            src_ip: IpAddr::from_str("192.168.0.1").unwrap(),
            dst_ip: IpAddr::from_str("8.8.8.200").unwrap(),
            src_port: 31337,
            dst_port: 80,
            ..Default::default()
        };

        assert!(a.is_in_homenet(&e1.src_ip));

        let table = vec![
            ((1, e1.clone(), r1.clone(), false), true),
            ((2, e1.clone(), r1.clone(), false), true)
        ];

        /*
		{1, e1, r1, s1, true}, {2, e1, r2, s1, true}, {3, e1, r3, s1, false}, {4, e1, r4, s1, false},
		{5, e1, r5, s1, false}, {6, e1, r6, s1, false}, {7, e1, r7, s1, true}, {8, e1, r8, s1, false},
		{9, e1, r9, s1, false}, {10, e2, r10, s1, false}, {11, e1, r11, s1, false},
		{12, e1, r12, s1, false}, {13, e1, r13, s1, false}, {14, e3, r14, s1, false},
		{15, e1, r15, s1, false}, {16, e1, r16, s1, false}, {17, e1, r17, s1, false},

         */

        for (validator, (case_id, event, rule, mutate_sdiff), expected) in table_test!(table) {
            let actual = rule.does_event_match(&a, &event, mutate_sdiff);

            validator
                .given(&format!("test_case: {}, ", case_id))
                .when("does_event_match")
                .then(&format!("it should be {}", expected))
                .assert_eq(expected, actual);
        }
    }
}