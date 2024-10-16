# rename dqy according to target triple
triple=$(rustc -vV | sed -n 's|host: ||p')
cp ./target/release/dqy ./target/release/dqy-$triple