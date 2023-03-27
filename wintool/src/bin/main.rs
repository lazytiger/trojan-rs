use wintool::adapter::get_adapters_addresses;

fn main() {
    unsafe {
        get_adapters_addresses(|adapter| {
            println!(
                "name:{}, description:{}, up:{}, ethernet:{}, index:{}, gateway:{:?}, dns:{:?}, dns_auto:{}, address:{:?}",
                adapter.name(),
                adapter.description(),
                adapter.is_up(),
                adapter.is_ethernet(),
                adapter.if_index(),
                adapter.gateway(),
                adapter.dns(),
                adapter.is_dns_auto(),
                adapter.address(),
            );
            false
        });
    }
}
