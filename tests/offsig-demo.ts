import { randomBytes } from 'crypto';
import * as anchor from '@project-serum/anchor';
import { Program } from '@project-serum/anchor';
import * as secp256k1 from 'secp256k1'
import { OffsigDemo } from '../target/types/offsig_demo';

describe('offsig-demo', () => {

  let provider = anchor.Provider.env()
  // Configure the client to use the local cluster.
  anchor.setProvider(provider);

  const program = anchor.workspace.OffsigDemo as Program<OffsigDemo>;

  it('Is initialized!', async () => {
    const tx = await program.rpc.initialize({});
    console.log("Your transaction signature", tx);
  });

  it('Is verified!', async () => {
    const msg = randomBytes(32)
    let privKey = randomBytes(32)
    let sigObj = secp256k1.ecdsaSign(msg, privKey)
    let pubKey = secp256k1.publicKeyCreate(privKey, false)

    const tx = await program.rpc.verify([...msg], [...sigObj.signature], [...pubKey], {});
    console.log("Your transaction signature", tx);
  });
});
