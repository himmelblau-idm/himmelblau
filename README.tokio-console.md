## Using the Taco Console

Install the console

`cargo install tokio-console`

Build the himmelblaud resolver with the needed tokio unstable features, and the console
enabled.

`RUSTFLAGS="--cfg tokio_unstable" cargo build --features himmelblaud/console`

Run himmelblaud - you can configure with console with the documented [environment variables](https://docs.rs/console-subscriber/latest/console_subscriber/struct.Builder.html#method.with_default_env)

Connect the console to himmelblaud - if you set `TOKIO_CONSOLE_BIND` in your environment, you can connect remotely.

`tokio-console`


