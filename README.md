# Packet Meta Classifier (pmc)
A customizable packet classifier for any protocol stack.

## Motivation
Inspect raw data in order to classify it is a simple task until you want to make it as fast as possible.
This performance increment is indirectly proportional to the code organization,
so when your high performance classifier grows it becomes a nightmare to organize, scale and debug it.
This library tries to solve this problem offering a statically resolved plugin-based solution
that decouple the main generic classification functionality from the classification user requirement.

## Features
- Generic: The library can be used for any purpose: e.g: classify traffic of internet, radio, bluetooth, etc,
- or even to make hard-drive memory inspection or image classification.
- Plugin based: Create your (analyzers/flows/expressions) implementing some
  [minor traits](pmc-core/src/base).
- Fast:
  - Rule analysis optimization: the packet will be gradually analyzed for the rules that require it.
  - No allocations (except in the case where a flow is required).
  - Statically plugin addition: The user analyzer/flow/expressions plugins do not required dynamic dispatch.
    They are built in along with the core library.
- Safety:
  - The API forces to the programmer to only define plugins in order to create classifiers,
  in a strict way, reducing the human error in the process and let the code well organized.
  - Thanks to *rust* inherit safety: no obfuscated coredumps.
- Easy testing: Fill a few properties on a struct and run the test.
- Pretty logs: Concised, with useful information, and full of colour!

## How this project is organized?
- [pmc-core](pmc-core): The library itself to build your classifier.
It contains two kind of APIs depending the kind of the developer is using it:
    - Trait based API: To build your classification plugins: analyzers, flows and expression values.
    - Usage API: In order to use the classifier: Creating the engine, defining rules, process packets, etc.
- [pmc-testing](pmc-testing): Contains utilities that you can use to test and run your the classifier.
- [classifiers](classifiers): Folder with the builtin classifiers availables using the pmc-core library.
Currently containing the [internet classifier](classifiers/internet),
a packet classifier for the internet protocol stack.

## Testing
To tests the available test suite, it is as simple as run `cargo test`.
Nevertheless, for a better testing experience it is recommended to enable the `testing-logs` feature.
The prefered command is the following:
```sh
cargo test --features "testing-logs" -- --nocapture --test-threads=1
```
*where `--nocapture` is for enable the standard output in the tests
and `--test-threads=1` to avoid mix the logs of different executions.*

If debugging requires more information to analyze certain test case, the `classifier-logs` feature
can also be enabled:
```sh
cargo test <name> --features "testing-logs classifier-logs" -- --nocapture --test-threads=1
```

*where `<name>` is the name of one of the available test cases (`cargo test -- --list` to list them).*
