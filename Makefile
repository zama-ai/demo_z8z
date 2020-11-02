build:
	RUSTFLAGS="-C target-cpu=native" cargo build --release
run:
	RUSTFLAGS="-C target-cpu=native" cargo run --release
test:
	RUSTFLAGS="-C target-cpu=native" cargo test --release test_homomorphic_key