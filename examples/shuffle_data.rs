use dum_cipher::dum_encryption;

fn main() {
    let data = b"Are you still able to read this? I hope it took you some effort.".to_vec();
    let shuffled = {
        let rotated = dum_encryption::rotate_data(data.clone(), false);
        dum_encryption::mirror_data(rotated)
    };
    
    println!("{}", String::from_utf8_lossy(&data));
    println!("{}", String::from_utf8_lossy(&shuffled));
}