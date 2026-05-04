#![cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]

pub(crate) fn parse_route_get_table(output: &str) -> Option<String> {
    let mut parts = output.split_whitespace();
    while let Some(part) = parts.next() {
        if part == "table" {
            return parts.next().map(str::to_string);
        }
    }
    None
}

pub(crate) fn outbound_bypass_table_from_route_get(output: &str) -> String {
    parse_route_get_table(output).unwrap_or_else(|| "main".to_string())
}

pub(crate) fn outbound_interface_from_route_get(output: &str) -> Option<String> {
    let mut parts = output.split_whitespace();
    while let Some(part) = parts.next() {
        if part == "dev" {
            return parts.next().map(str::to_string);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_android_route_get_table_name() {
        let out = "8.8.8.8 via 192.168.1.1 dev wlan0 table wlan0 src 192.168.1.23 uid 0";

        assert_eq!(parse_route_get_table(out), Some("wlan0".to_string()));
    }

    #[test]
    fn parses_android_route_get_numeric_table() {
        let out = "1.1.1.1 via 10.9.0.1 dev rmnet_data0 table 1017 src 10.9.1.2";

        assert_eq!(parse_route_get_table(out), Some("1017".to_string()));
    }

    #[test]
    fn route_get_without_table_uses_implicit_main() {
        let out = "1.1.1.1 via 192.168.0.1 dev eth0 src 192.168.0.2 uid 1000";

        assert_eq!(parse_route_get_table(out), None);
        assert_eq!(outbound_bypass_table_from_route_get(out), "main");
    }
}
