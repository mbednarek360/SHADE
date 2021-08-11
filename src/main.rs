mod shade;
use std::env;
use std::fs;
use std::time;

// usage: shade input.txt output.bin password <decrypt>
fn main() {
    let args: Vec<String> = env::args().collect();
    let key = [0u8; 32];
    let inp = fs::read(&args[1]).unwrap();
    let start = time::Instant::now();
    let out = shade::crypt_message(key, inp, args[3] == "d").unwrap();
    let time = start.elapsed().as_micros();
    println!(
        "Processed {}bytes in {}ms at {}B/s",
        out.len(),
        time / 1000,
        (out.len() * 1000 * 1000) as u128 / time
    );
    fs::write(&args[2], out).unwrap();
}
