# Internet Classifier
A classifier for the *tcp-ip-stack* using the [pmc-core](../../pmc-core) library.

## Current classifiers:
- IP
- UDP
- TCP
- HTTP

## Testing
- Component tests can be found in `tests/component.rs`
- Captures can be found in `tests/captures/`

To know how to test it, read the main [Testing](../.././README.md#testing) section.

## Examples

### Real traffic example
This example inspects a real network interface and classify the traffic.

Steps:
1. Use `ifconfig` or something similar to find an interface to inspect those packets.
2. Run the example. Do not run the typical `cargo run --examples` because the executable need privileges to inspect the network interface. Instead, run the following (Linux):

  ```sh
  cargo build --examples --features testing-logs
  sudo ./target/debug/examples/real_traffic <interface-name>
  ```
  *(Similar commands in MacOS and Windows)*

3. Navigate to [`http://example.com`](http://example.com) in your browser.

You can found the code [here](examples/real_traffic/main.rs) to inspect the classification rules.
