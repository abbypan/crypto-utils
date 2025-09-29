
use std::error::Error;
use twenty_first::{tip5::Tip5, prelude::{Digest, BFieldElement}};

// see also: https://github.com/maxirmx/tip5/blob/main/samples/tip5-rust/src/main.rs

fn parse_number(input: &str, is_hexstr: bool) -> Result<u64, Box<dyn Error>> {
    let value = if is_hexstr { //hex
        u64::from_str_radix(input, 16)?
    } else { //dec
        input.parse::<u64>()?
    }
    ;
    Ok(value)
}


fn map_u64arr_to_bfvec(irr: &[u64]) -> Result<Vec<BFieldElement>, Box<dyn Error>> {
    let arr :  Vec<BFieldElement> = 
        irr.iter()
        .map(|&x| BFieldElement::new(x))
        .collect();
    Ok(arr)
}

fn map_bfvec_to_digest(arr: Vec<BFieldElement>) -> Result<Digest, Box<dyn Error>> {
    let arr2: [BFieldElement; 5] = arr.try_into().expect("Vec length != 5");
    Ok(Digest::new(arr2))
}

fn map_u64arr_to_digest(irr: &[u64]) -> Result<Digest, Box<dyn Error>> {
    let irr2 : [u64; 5] = irr.try_into().expect("Slice has wrong length");
    let arr2: [BFieldElement; 5] = irr2.map(|x| BFieldElement::new(x));
    Ok(Digest::new(arr2))
}


fn main() -> Result<(), Box<dyn Error>> {
    let frt_u64_array: [u64; 5] = [1, 2, 3, 4, parse_number("5",false)?];
    //let frt_bf = map_u64arr_to_bfvec(&frt_u64_array)?;
    //let frt_dgst = map_bfvec_to_digest(frt_bf)?;
    let frt_dgst = map_u64arr_to_digest(&frt_u64_array)?;

    let snd_u64_array: [u64; 5] = [6, 7, 8, 9, parse_number("A", true)?];
    let snd_dgst = map_u64arr_to_digest(&snd_u64_array)?;

    let trd_u64_array: [u64; 5] = [11, 12, 13, 14, 15];
    let trd_dgst = map_u64arr_to_digest(&trd_u64_array)?;

    println!("first {:?}", frt_u64_array); 
    println!("second {:?}", snd_u64_array);

    let result = Tip5::hash_pair(frt_dgst, snd_dgst);
    println!("pair Digest({})", result.to_string());

    println!("third {:?}", trd_u64_array);

    let mut digests = Vec::new();
    digests.extend_from_slice(&frt_dgst.values());
    digests.extend_from_slice(&snd_dgst.values());
    digests.extend_from_slice(&trd_dgst.values());
    let result2 = Tip5::hash_varlen(&digests);
    println!("varlen Digest({})", result2.to_string());

    Ok(())
}
