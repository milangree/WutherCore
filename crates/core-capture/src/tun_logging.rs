use crate::engine::CapturePlan;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootTunLogSummary {
    pub interface_name: String,
    pub stack: String,
    pub mtu: u32,
    pub tun_v4: String,
    pub tun_v6: String,
    pub auto_route: bool,
    pub auto_redirect: bool,
    pub strict_route: bool,
    pub hijack_dns: bool,
    pub table: u32,
    pub rule_priority: u32,
    pub output_mark: u32,
    pub route_mode: &'static str,
    pub route_address_count: usize,
    pub route_address_set_count: usize,
    pub route_exclude_count: usize,
    pub route_exclude_set_count: usize,
}

pub fn root_tun_summary(plan: &CapturePlan) -> RootTunLogSummary {
    RootTunLogSummary {
        interface_name: plan.interface_name.clone(),
        stack: format!("{:?}", plan.stack),
        mtu: plan.mtu,
        tun_v4: plan.tun_v4_addr_cidr(),
        tun_v6: plan.tun_v6_addr_cidr().unwrap_or_default(),
        auto_route: plan.auto_route,
        auto_redirect: plan.auto_redirect,
        strict_route: plan.strict_route,
        hijack_dns: plan.hijack_dns,
        table: plan.iproute2_table_index,
        rule_priority: plan.iproute2_rule_index,
        output_mark: plan
            .auto_redirect_marks
            .output
            .unwrap_or(core_config::model::DEFAULT_AUTO_REDIRECT_OUTPUT_MARK),
        route_mode: root_tun_route_mode(plan),
        route_address_count: plan.route_addresses.len(),
        route_address_set_count: plan.route_address_set.len(),
        route_exclude_count: plan.route_exclude_addresses.len(),
        route_exclude_set_count: plan.route_exclude_address_set.len(),
    }
}

pub fn root_tun_route_mode(plan: &CapturePlan) -> &'static str {
    if plan.route_addresses.is_empty() || !plan.route_address_set.is_empty() {
        "catch-all"
    } else {
        "static-route-address"
    }
}

#[cfg(test)]
mod tests {
    use crate::engine::CapturePlan;

    fn base_plan() -> CapturePlan {
        CapturePlan::from_config(&core_config::model::Capture {
            on: true,
            method: core_config::model::CaptureMethod::VirtualNic,
            stack: core_config::model::CaptureStack::Mixed,
            tun: core_config::model::TunInboundOptions {
                inet6: true,
                ..Default::default()
            },
            ..core_config::model::Capture::default()
        })
        .unwrap()
    }

    #[test]
    fn root_tun_summary_reports_policy_route_mode_and_counts() {
        let mut plan = base_plan();
        plan.route_exclude_addresses = vec!["1.1.1.1/32".parse().unwrap()];
        plan.route_exclude_address_set = vec!["geoip-cn".into()];

        let summary = super::root_tun_summary(&plan);

        assert_eq!(summary.route_mode, "catch-all");
        assert_eq!(summary.route_exclude_count, 1);
        assert_eq!(summary.route_exclude_set_count, 1);
        assert_eq!(summary.table, plan.iproute2_table_index);
        assert_eq!(summary.rule_priority, plan.iproute2_rule_index);
    }

    #[test]
    fn root_tun_summary_reports_static_whitelist_route_mode() {
        let mut plan = base_plan();
        plan.route_addresses = vec!["8.8.8.8/32".parse().unwrap()];

        let summary = super::root_tun_summary(&plan);

        assert_eq!(summary.route_mode, "static-route-address");
        assert_eq!(summary.route_address_count, 1);
    }
}
