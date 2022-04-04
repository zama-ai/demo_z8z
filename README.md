# Demo Z/8Z

This demo uses [Concrete library](https://github.com/zama-ai/concrete) to implement exact homomorphic computation with 3-bit integers.

The following functions are implemented:

- addition between a ciphertext and a constant
- subtraction between a ciphertext and a constant
- multiplication between a ciphertext and a constant
- addition between two ciphertexts
- subtraction between two ciphertexts
- multiplication between two ciphertexts
- max between two ciphertexts

## Disclaimer

This demo is for an outdated version of Concrete (0.1.5). New crates, about to be published, will
completely change the demo code, next update will be done after the new crates are released.

## Install

To run this demo, you have to install Rust and Concrete Library.

## Key Generation

By default in the [main](src/main.rs#L13-L14) and in the [test](src/z8z/tests.rs#L426-L427) we call the `setup` function which takes quite some time to generate the bootstrapping key and to write it in a file.
It only needs to be done once, then you can use the `setup_load` function instead which will simply load the key from the local file.

## Makefile

- `make test`: to run hundreds of homomorphic additions multiplications and more
- `make build`: to build
- `make run`: to run the simple main program

## Links for Concrete Library

- [documentation](https://concrete.zama.ai)
- [whitepaper](http://whitepaper.zama.ai)

## License

This software is distributed under the AGPL-v3 license. If you have any question, please contact us at hello@zama.ai.
