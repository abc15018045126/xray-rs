// Module: features\mod.rs

pub mod dns;
pub mod extension;
pub mod feature;
pub mod inbound;
pub mod outbound;
pub mod policy;
pub mod routing;
pub mod stats;

#[cfg(test)]
pub mod feature_test;

pub use dns::{
    client_type, fake_dns_type, DnsClient, FakeDnsEngine, FakeDnsFeature, IPOption,
    LocalDnsClient, RCodeError, DEFAULT_TTL, FAKE_IPV4_POOL, FAKE_IPV6_POOL,
};
pub use extension::{
    observatory_type, BurstObservatory, ContextReceiver, Observation, ObservatoryFeature,
};
pub use feature::{
    Feature, TYPE_DISPATCHER, TYPE_DNS_CLIENT, TYPE_FAKE_DNS, TYPE_INBOUND_MANAGER,
    TYPE_OBSERVATORY, TYPE_OUTBOUND_MANAGER, TYPE_POLICY_MANAGER, TYPE_ROUTER,
    TYPE_STATS_MANAGER,
};
pub use inbound::{manager_type as inbound_manager_type, InboundHandler, InboundManager, InboundResult};
pub use outbound::{
    manager_type as outbound_manager_type, HandlerSelector, OutboundHandler, OutboundManager,
};
pub use policy::{
    default_buffer_policy, default_policy, manager_type as policy_manager_type,
    session_default, Buffer, DefaultManager as DefaultPolicyManager, Policy, PolicyManager,
    SessionPolicy, Stats as PolicyStats, SystemPolicy, SystemStats, Timeout,
};
pub use routing::{
    dispatcher_type, router_type, Balancer, BalancerFeature, BalancerOverrider,
    BalancerPrincipleTarget, DefaultRoute, DefaultRouter, Dispatcher, DispatcherFeature,
    ResolvableContext, Route, RouteContext, Router, RouterFeature, RoutingContext,
    SessionRouteContext,
};
pub use stats::{
    get_or_register_counter, get_or_register_online_map, manager_type as stats_manager_type,
    Counter, DefaultOnlineMap, DefaultStatsManager, NoopStatsManager, OnlineMap,
    StatsManager, StatsManagerTrait,
};
