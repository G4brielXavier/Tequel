// use crate::hash::TequelHash;

// pub fn merkle_nodes(a: &[u8], b: &[u8], c: &[u8], d: &[u8]) -> [[u8; 48]; 7] {

//     let mut teq = TequelHash::new();
    
//     let mut nodes = [[0u8; 48]; 7];

//     let mut stch_pad = [0u8; 96];

//     nodes[3] = teq.tqlhash_raw(a);
//     nodes[4] = teq.tqlhash_raw(b);
//     nodes[5] = teq.tqlhash_raw(c);
//     nodes[6] = teq.tqlhash_raw(d);

//     stch_pad[..48].copy_from_slice(&nodes[3]);
//     stch_pad[48..].copy_from_slice(&nodes[4]);
//     nodes[1] = teq.tqlhash_raw(&stch_pad);

//     stch_pad[..48].copy_from_slice(&nodes[5]);
//     stch_pad[48..].copy_from_slice(&nodes[6]);
//     nodes[2] = teq.tqlhash_raw(&stch_pad);

//     stch_pad[..48].copy_from_slice(&nodes[1]);
//     stch_pad[48..].copy_from_slice(&nodes[2]);
//     nodes[0] = teq.tqlhash_raw(&stch_pad);

//     nodes

// }