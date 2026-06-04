// Transaction-level decode against a real on-chain Conway-era PoE transaction.
//
// The fixture below is the verbatim CBOR of a confirmed Cardano transaction
// carrying a Label 309 record under metadata label 309. It exercises the
// byte-faithful body/witness slicing in `cbor-walker`, the vkey-witness
// signature verification, and the JSON-safe transaction summary.

import { describe, expect, it } from 'vitest';

import { decodeCbor } from '@cardanowall/crypto-core/cbor';
import { blake2b256 } from '@cardanowall/crypto-core/hash';

import { sliceLabel309Value, sliceTxComponents } from './cbor-walker';
import { decodeTxSummary, decodeTxWitnesses } from './tx-witnesses';
import { bytesToHex } from '../hex';

// Confirmed Conway-era transaction CBOR. `blake2b256(txBody)` of the sliced
// body equals the on-chain transaction hash asserted below.
const TX_HEX =
  '84a400d9010281825820c57958d87303c88b02c96ec2a2e0821903b4757180408c3023a7895025a4aad700018182581d607a' +
  '7e59bef59f44623959b24113e636c97121f764f25007e66409fad41b000000024e3a124f021a0003aecd075820a86bfe8d91' +
  '8a5e64d397621bd204d955d20d158995cac4963f0c2e55c3bae300a100d9010281825820352be5986df143119e0be1d5a1d9' +
  '595076b5f712ac009e1ad564400212835ac158409b939bf6b289451f5712efb46ea00fd87a3c07e395789ae5645477820847' +
  '6d591f450d0796f342924182a8ecf3a65e659870f163e3a4944f47f45196e79adb06f5a1190135981a5840a3617601647369' +
  '677381a16a636f73655f7369676e31825840845826a201270458205e9eb27f12e032145e0e79dda0c9c0a8b01027cc407b67' +
  'daff9c0bcd7144584010eda0f658406f3d245a9bf751308c276aae9b87f129a29c47582dd3d3cfb0f01c7873be2ff8ac0b74' +
  '022a305cc77eaaf8703cbb376ca27639507557e1981e315840eea055733eb13002656974656d7381a363656e63a6636b656d' +
  '6e6d6c6b656d3736387832353531396461656164727863686163686132302d706f6c79313330355840656e6f6e636558188c' +
  '793d1c6f8be407a59d16563d0ab50bf91b5b77aa5d051d65736c6f747381a2647772617058305f947396bfd5dfd4f0b13c71' +
  'c6907dfafb5840ac66426b96397503235b01548c7b145974eaf90ab03079d4572995a0a0932d666b656d5f63749258406cd3' +
  '224d019e1ba27402c2b5074ce0d9f4935502acca7c584020263f2110f2ec868e6ab573f373e1ed4f0da3d5e5786fe5a9c594' +
  'ef440058a83498b585d2a54cef905840f0cd3323d9ddcb5584111ac87bde55c09f8cad529458401cbb12fd7b29d76828b9ad' +
  '58ea3a71a155a42d10755eed7bc813a67eb082e54ed2aa808bb81e972a27ce4d58400012bbf28d21942fb2aeb2bb7954a33c' +
  '0da85e584043f4b997781c4bdcec1e0cf12ddfd1ce24226388cb227374b6fad561131738c832247d977655622a12e0b3bc12' +
  '5840424e7f4616820b5cf9ac66faf8daf56ef05840c6cdcf7faded3618fb1dc98d4a37376b7a797eaa1676bc920fd90facc5' +
  'a114e572ca80d340b089c9e1e667164fdebe58400216107d550d6a9cdf46bbb50b634e58403f4085f4897cbc0cca121d4a67' +
  '1d87cabfcf90f9f49d64f29fa8bf2941e213b4852d99d2e1c5d6684c3e72221f11606796584072145d1393275bb6e8b58ddb' +
  'f15840813f68cf0607c92ea8f166c556b81bdd93c7d61b4d1757891e748306417e097f17da4a3d8c936f62482786ef9ea5d4' +
  'ed52c784584047deabfcae711f7f1fb56e5840406b08e2f85ce02281f32c2f4d7c24f43662e189e93837e761079ff2412499' +
  '4c4e92091e5ba0d5ef987bf47f0fee2e50d3b34ed7a25840938a89e6db94194b035840476392ecb8d45b70ad1c17864f1d98' +
  '8af6bb95efabe340f839714a9fc0e8924df4a9b4d271321526019b5b32dbd8af98926b96ec63216f584000c0cbbee9e37958' +
  '40a0f1837ce0cc70b7521e24466cb3871075829662687fa68fd4b888f8a4e41ca8c454cdeef86ccd7b53926b44a395fd102d' +
  '8f9568fbae5b603258401d1359491e58408973059f3d079af9a59a6dd0fc152e63347970ffe93100c40e3d4797391a55d578' +
  '5f94fd061bd12268a92ad0354f9f75871a450350fc8f9677d4dd58403ebd1f5840fe4a6dad870ca001a1e1faf95b3bb78448' +
  'afd31832541e324c1b8e931b05e254d763fb5f3ba3a1f790bd58aeb86421d17c0c97eeeab20114e05d3ceba05840cb584085' +
  '0f9382b17b54c1a6b64f83afe03954c289a598e6e6a2b0aa270e14670de548a8f66543e2d7a5efe958f318df764b49ef10a7' +
  '5cb64db68439f5fab2c5a15458584040d45465d9388ead749e84c36d0ab2dbc131596d75003c3f51f0793bb9c9e5d33e20d8' +
  'df968f259d0346c56452f04556f16c7cd26bbddcc7fa349cbec2e70955584046584026b4a37eb096cd45308b7c74a8c1e203' +
  '2ad7da40ceb3d32625d6d9dd44fa43c473094426fef7d0bbdd36c8a850384d2883e76e7e2bf2f054135e3269e5584036197d' +
  '5840d7d4cb68932a34db521dac3cc257993dfc076336f27300f2cd9de0ac73b73e674f1c9b0ad4f85cd47b256f543ef52b57' +
  '33d692f7f70ec04fa1b36d58408d6d472c6158403d10bdb252ebe73a9ca7d49e9f40ae555384f5105babe3e8c193f7edf3ac' +
  '07f49566c6f6fe73276032650f15fd97db880d9d6faa7c1f6ae82b5840d1c8ce3237fc085840221ccfa7f796c185813623d9' +
  '1959aef00e5d9d2c32e86c6d891c9735366a3318a9aef3a090c92290ca72e414531130aa7f4145cdd67fcb5840a10234018f' +
  '828786bf5820e19ce0ee92872b85b3ae9e39e7b3a8dcbece8812d021ea1eaa2462419602b82266736368656d650169736c6f' +
  '74735f6d61635820f25840cc3436797e6441560749d9a291c100c168f86efb5fc2eff7b32f5580e3f32a6475726973818178' +
  '3061723a2f2f7041355345454243513762494e533478666e475840316f777278376b786242504d3134486f4c433165513250' +
  '5566686173686573a268736861322d32353658203fffeff73a32793ca731c40c30431b6498e3a7b8055839bb0fce4fab833d' +
  'a51b2b956b626c616b6532622d3235365820487f9f8e1c7293c5ba5d956461ecf66f089115c28473e6c5f2c47f14067eb02e';

const EXPECTED_TX_HASH = 'e71daa29817f667f310b3484a2c39914bc1fed02d68eba28a4d7ca61578baf1c';

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const TX = hexToBytes(TX_HEX);

describe('sliceTxComponents — byte-faithful tx body slice', () => {
  it('produces a body slice whose blake2b256 equals the on-chain tx hash', () => {
    const { txBody } = sliceTxComponents(TX);
    expect(bytesToHex(blake2b256(txBody))).toBe(EXPECTED_TX_HASH);
  });

  it('collects every aux metadata label, sorted ascending', () => {
    const { auxMetadataLabels } = sliceTxComponents(TX);
    expect(auxMetadataLabels).toEqual([309]);
  });

  it('leaves sliceLabel309Value byte-identical (a Label 309 record map)', () => {
    const fromHelper = sliceLabel309Value(TX);
    const { label309 } = sliceTxComponents(TX);
    expect(fromHelper).not.toBeNull();
    // sliceLabel309Value must keep returning exactly the bytes
    // sliceTxComponents finds — the refactor cannot change its output.
    expect(label309).not.toBeNull();
    expect(Array.from(label309!)).toEqual(Array.from(fromHelper!));
    // The reassembled value decodes as a Label 309 record: { "v": 1, … }.
    const record = decodeCbor(label309!) as Record<string, unknown>;
    expect(record['v']).toBe(1);
    expect('items' in record).toBe(true);
  });
});

describe('decodeTxWitnesses', () => {
  it('verifies the single vkey witness against the tx body', () => {
    const { txBody, witnessSet } = sliceTxComponents(TX);
    const witnesses = decodeTxWitnesses(witnessSet, txBody);
    expect(witnesses).toHaveLength(1);
    expect(witnesses[0]!.type).toBe('vkey');
    expect(witnesses[0]!.vkey).toBe(
      '352be5986df143119e0be1d5a1d9595076b5f712ac009e1ad564400212835ac1',
    );
    expect(witnesses[0]!.key_hash).toBe('7a7e59bef59f44623959b24113e636c97121f764f25007e66409fad4');
    expect(witnesses[0]!.signature_valid).toBe(true);
  });

  it('reports signature_valid:false when the body is tampered (one flipped byte)', () => {
    const { txBody, witnessSet } = sliceTxComponents(TX);
    const tampered = txBody.slice();
    tampered[5] = (tampered[5]! ^ 0x01) & 0xff;
    const witnesses = decodeTxWitnesses(witnessSet, tampered);
    expect(witnesses).toHaveLength(1);
    // The witness is still surfaced (it describes the authoriser) but the
    // signature no longer verifies against the mutated body.
    expect(witnesses[0]!.signature_valid).toBe(false);
    expect(witnesses[0]!.vkey).toBe(
      '352be5986df143119e0be1d5a1d9595076b5f712ac009e1ad564400212835ac1',
    );
  });
});

describe('decodeTxSummary', () => {
  it('decodes fee, counts, and the output address + amount as JSON-safe values', () => {
    const { txBody, witnessSet } = sliceTxComponents(TX);
    const summary = decodeTxSummary(txBody, witnessSet, 'preprod');
    expect(summary.fee_lovelace).toBe('241357');
    expect(summary.input_count).toBe(1);
    expect(summary.output_count).toBe(1);
    expect(summary.outputs).toHaveLength(1);
    expect(summary.outputs[0]!.address.startsWith('addr_test1')).toBe(true);
    expect(summary.outputs[0]!.lovelace).toBe('9902363215');
    expect(summary.total_output_lovelace).toBe('9902363215');
    // No native scripts / Plutus witnesses on this tx.
    expect(summary.script_witness_count).toBe(0);
  });
});
