from brownie import web3
from collections import Counter
from toolz import valfilter
from tqdm import tqdm, trange
from eth_abi import decode_single
import json
from pprint import pprint


# contract address that we can't decode the input data
UNABLE_TO_DECODE = [
    '0x103675510a219bd84CE91d1bcb82Ca194D665a09', #Argent
    '0x545B5f104Ce8DA0f37e63e5A977043291f790e04',
    '0x9a8DB724493AF5B607F896Db1DB5dAfB4EdAf154',
    '0xa5361000C661cffC4aFda1dC075e6cDf554494a9',
    '0xcb6B6775d2Ff480173149afd4Bb1B1ebE4e68705', #Authereum
    '0xFc52320B42733D7af775F2D6dAB1b1Daa76FC83f',
    '0x3047570d07521E5967EA1909270769F90fdF1f05',
    '0xbFC842e1dd050FCFD7711BB7E4A87716c10C64a4',
    '0x0875385D86CAcF735b81f110Fd37755EACc8c30b',
    '0x8A6A35dB19567e21580E28FEb3994e0dE6b930D8',
    '0x8e3c62EDA37287be1daA40dB00dDaa13028D52ce',
    '0x544965987424c0F2b0d7743553a68C88f32749fe',
    '0x9505538D02eA45b93d531FEB2D3EBaFDAbC74607',
    '0x15Bb78ED1a9AC8b3C02869dECeBC72c1CB6C313D',
    '0xd40A7f8EfbdfBD5c9c2428ad81E8Db6D53292E35',
    '0x0ebC541c3f518d23d6B02b4Ce1A9147D551D3660',
    '0x763E365A606527fa4511b0e83d8252F46c4DdB56',
    '0xa664693d89B7086E9f7a4299E3B9cAE74b54a313',
    '0xf5E48DFd5Bc1e548D7417D1F569774aF767f17d9',
    '0xFE3030eE66756F40FCc9873539feeE1Ea1D7e1E1',
    '0xFF44cf4ed99695AfdfeDB3fe3fAF8020ab9ABf81',
    '0x21EFB8C09cb22Fd9761B5C280F8C8AEc03502e06',
    '0x681D9F765039AAFD4aeE1A0CD359340497fbfe3F',
    '0x055dBBe0a2FCA92A67DE714A5ECb13D420f934f0',
    '0xD5C0d8FFc9C90b6dfc55614a5c5b844214c99716',
    '0x24553725F1dC1548D3a046e49daE2e44B09425e3',
    '0x94C2e8fee611da4cfec9dCD34Daa88465bcd1aC9', #Authereum
    '0x1a0606300CeCA332B356a3fcFe99471B5a7f22BA',
    '0xe920B3F96Cb2bF1Ee9ee8921837de08273724242'
]

# contract addresses without abi on etherscan.io
NO_ABI_AVAILABLE = [
    '0x9E7D5a22b213cD77aa26622C7154E5f1810929E0',
    '0x62c9b69fB4252272aAFc30241E696Ea56116c4f1',
    '0x19cC75e2899480B802cA46A053c41C53dBC64230',
    '0x89FB5Fa10b2171C0A558ff6fA0df6FAf086c3E52',
    '0x5ca5007BE6743a1516f9a8A7a5e18027971130D4',
    '0xcda99344041A5CE1aF1654d48e9c1cd99da0ef7B',
    '0xe920B3F96Cb2bF1Ee9ee8921837de08273724242',
    '0x1a0606300CeCA332B356a3fcFe99471B5a7f22BA',
    '0x40DDE6092a77eC2d00eB4fa14f0c5d92d835d673'
]

SKIP_ADDRESSES = NO_ABI_AVAILABLE + UNABLE_TO_DECODE

def getFunctionSignature(tx_input):
    '''
        takes tx input data and returns the hex signature
    '''
    if type(tx_input) == str:
        return tx_input[:10]
    elif type(tx_input) == bytes:
        return '0x' + tx_input[:4].hex()
    return tx_input[:4].hex()

def getArgsFromDefinition(definition):
    '''
        takes function definition and returns the list of args of the function
    '''
    return f'({"".join(definition.split("(")[1:])}'

def strToFunctionSignature(definition):
    '''
        takes function definition and computes the hex signature
    '''
    return web3.keccak(text=definition)[:4].hex()

class TxDataParser:
    def __init__(self, definition, names, want_fields, is_meta_transaction=False, use_sender_address=False):
        self.definition = definition
        self.names = names 
        self.want_fields = want_fields
        self.args = getArgsFromDefinition(definition)
        self.signature = strToFunctionSignature(definition)
        self.is_meta_transaction = is_meta_transaction
        self.use_sender_address = use_sender_address

    def parse_tx(self, tx_data):
        if type(tx_data) == str:
            tx_data = bytes.fromhex(tx_data[10:])
        elif type(tx_data) == bytes:
            tx_data = tx_data[4:]            
        result = decode_single(self.args, tx_data)
        result = dict(zip(self.names, result))
        return [result.get(want) for want in self.want_fields]

# Parsers based on function signatures
PARSERS = {
    '0x77f61403': TxDataParser(
                    definition='mint(string,address,uint256,bytes32,bytes)', 
                    names=('_symbol', '_recipient', '_amount', '_nHash', '_sig'),
                    want_fields=('_recipient','_amount')),
    '0xd039fca1': TxDataParser(
                    definition='executeMetaTransaction(address,bytes,string,string,bytes32,bytes32,uint8)', 
                    names=('userAddress', 'functionSignature', 'message', 'length', 'sigR', 'sigS', 'sigV'),
                    want_fields=('userAddress', 'functionSignature'),
                    is_meta_transaction=True),
    '0x29349116': TxDataParser(
                    definition='mintThenSwap(uint256,uint256,uint256,int128,address,uint256,bytes32,bytes)',
                    names=('_minExchangeRate','_newMinExchangeRate','_slippage','_j','_coinDestination','_amount','_nHash','_sig'),
                    want_fields=('_coinDestination', '_amount')),
    '0xa318f9de': TxDataParser(
                    definition='mintThenDeposit(address,uint256,uint256[3],uint256,uint256,bytes32,bytes)',
                    names=('_wbtcDestination', '_amount', '_amounts', '_min_mint_amount', '_new_min_mint_amount', '_nHash', '_sig'),
                    want_fields=('_wbtcDestination', '_amount')),
    '0x74955c42': TxDataParser(
                    definition='mintThenSwap(uint256,uint256,uint256,address,uint256,bytes32,bytes)',
                    names=('_minExchangeRate', '_newMinExchangeRate', '_slippage', '_wbtcDestination', '_amount', '_nHash', '_sig'),
                    want_fields=('_wbtcDestination', '_amount')),
    '0xdcf0bb3a': TxDataParser(
                    definition='mintThenDeposit(address,uint256,uint256[2],uint256,uint256,bytes32,bytes)',
                    names=('_wbtcDestination', '_amount', '_amounts', '_min_mint_amount', '_new_min_mint_amount', '_nHash', '_sig'),
                    want_fields=('_wbtcDestination', '_amount')),
    '0x0bfe8b92': TxDataParser(
                    definition='recoverStuck(bytes,uint256,bytes32,bytes)',
                    names=('encoded', '_amount', '_nHash', '_sig'),
                    want_fields=('encoded', '_amount'), # returning encoded field as placeholder to be replaced with sender address
                    use_sender_address=True),
    '0x834a7182': TxDataParser(
                    definition='mintThenSwap(uint256,address,uint256,bytes32,bytes)',
                    names=('_minWbtcAmount', '_wbtcDestination', '_amount', '_nHash', '_sig'),
                    want_fields=('_wbtcDestination', '_amount')),
    '0x47f701e7': TxDataParser(
                    definition='mintRenBTC(address,uint256,uint256,uint256,bytes32,bytes)',
                    names=('_recipient', '_gasFee', '_serviceFeeRate', '_amount', '_nHash', '_sig'),
                    want_fields=('_recipient', '_amount')),
    '0x0f5b02cd': TxDataParser(
                    definition='mintDai(uint256,bytes,uint256,uint256,bytes32,bytes)',
                    names=('_dart', '_btcAddr', '_minWbtcAmount', '_amount', '_nHash', '_sig'),
                    want_fields=('_btcAddr', '_amount'),# returning _btcAddr field as placeholder to be replaced with sender address
                    use_sender_address=True),
    '0x2012aca7': TxDataParser(
                    definition='deposit(bytes,uint256,bytes32,bytes)',
                    names=('_msg', '_amount', '_nHash', '_sig'),
                    want_fields=('_msg', '_amount'),# returning _msg field as placeholder to be replaced with sender address
                    use_sender_address=True),
    '0xec369f7d': TxDataParser(
                    definition='depositbtc(address,bytes,uint256,bytes32,bytes)',
                    names=('_user', '_msg', '_amount', '_nHash', '_sig'),
                    want_fields=('_user', '_amount')),
    '0xaacaaf88': TxDataParser(
                    definition='execute(address,bytes,uint256,bytes,uint256,uint256)', 
                    names=('_wallet', '_data', '_nonce', '_signatures', '_gasPrice', '_gasLimit'),
                    want_fields=('_wallet', '_data'),
                    is_meta_transaction=True),
}



GatewayABI = json.load(open(f"./interfaces/Gateway.json","r"))
BTC_GATEWAY_ADDRESS = "0xe4b679400F0f267212D5D812B95f58C83243EE71"
BTCGATEWAY = web3.eth.contract(BTC_GATEWAY_ADDRESS, abi=GatewayABI)

# block number the gateway contract got deployed 
# https://etherscan.io/tx/0x697063909e68c0f9230f6015aed0332de2bbf660ca44c19d19e7fd9888f4cf66
START_BLOCK = 9737055
SNAPSHOT_BLOCK = 11146722



def getMintersInfo(tx, second_pass=False):
    signature = getFunctionSignature(tx['input'])
    parser = PARSERS.get(signature, None)
    if parser is None:
        print(f"No Match for tx signature {tx['hash'].hex()}")
        return None 
    want_fields = parser.parse_tx(tx['input'])
    if parser.is_meta_transaction and second_pass == False:
        user_address, tx_data = want_fields
        tx_copy = tx.__dict__.copy()
        tx_copy['input'] = tx_data
        return getMintersInfo(tx_copy, second_pass=True)
    if parser.use_sender_address:
        want_fields[0] = tx.get("from")
    user_address, amount = want_fields
    return (user_address, amount)


# code from https://github.com/andy8052/badger-merkle/blob/master/scripts/snapshot.py
# events log doesn't contain the minter's address, have to get it from the tx input data
def get_renbtc_mint():
    mints = Counter()
    stats = Counter()
    for start in trange(START_BLOCK, SNAPSHOT_BLOCK, 1000):
        end = min(start + 999, SNAPSHOT_BLOCK)
        # getting LogMint events from the renvm btcgateway
        logs = BTCGATEWAY.events.LogMint().getLogs(fromBlock=start, toBlock=end)
        for log in logs:
            # contract address that interacted with btcgateway
            contract_address = log['args']['_to']
            # skip the addresses that we can't decode 
            if contract_address in SKIP_ADDRESSES:
                stats['contracts_skipped'] += 1
                continue
            # get transaction of the event to read the input data
            tx = web3.eth.getTransaction(log.transactionHash.hex())
            # checking skip addresses again, because sometimes log['args']['_to'] != tx.to
            if tx.to in SKIP_ADDRESSES:
                stats['address_skipped'] += 1
                continue            

            # parse the user_address and amount
            result = getMintersInfo(tx)
            if result is None:
                stats['empty'] += 1
                print(f"Got No result {tx.hash.hex()}")
                continue
            user_address, amount = result
            mints[user_address] += amount

    filteredMints = valfilter(bool, dict(mints.most_common()))
    print(len(filteredMints))
    print(f"STATS: {dict(stats.most_common())}")
    return filteredMints

      

def main():
    # uncomment to rescan the blockchain, it takes about ~30mins because it has to retrieve tx data for each mint event
    # new_renbtc_minters_data = get_renbtc_mint()
    # with open('./snapshot/renbtcMinters_NEW.json', 'w') as fp:
    #     json.dump(new_renbtc_minters_data, fp)

    # prescanned data
    with open('./snapshot/renbtcMinters_NEW.json', 'r') as fp:
        new_renbtc_minters_data = json.load(fp)

    with open('./snapshot/renbtcMinters.json', 'r') as fp:
        old_renbtc_minters_data = json.load(fp)
    
    with open('./snapshot/final.json', 'r') as fp:
        final = json.load(fp)

    
    # converting all addresses to ChecksumAddress just incase
    old_renbtc_minters_addresses = set([web3.toChecksumAddress(address) for address in set(old_renbtc_minters_data.keys())])
    new_renbtc_minters_addresses = set([web3.toChecksumAddress(address) for address in set(new_renbtc_minters_data.keys())])
    final_snapshot_addresses = set([web3.toChecksumAddress(address) for address in set(final.keys())])


    in_new_but_not_in_old = new_renbtc_minters_addresses - old_renbtc_minters_addresses
    renbtc_minters_notin_final = new_renbtc_minters_addresses - final_snapshot_addresses

    # double check the subtraction logic above
    missing = Counter()
    for address in new_renbtc_minters_addresses:
        if address not in old_renbtc_minters_addresses:
            missing['oldminters'] += 1
        if address not in final_snapshot_addresses:
            missing['finalsnapshot'] += 1

    assert missing['oldminters'] == len(in_new_but_not_in_old)
    assert missing['finalsnapshot'] == len(renbtc_minters_notin_final)


    print(f"Number of renbtc minters not credited for minting: {len(in_new_but_not_in_old)}")
    print(f"Number of minters that are not included in final.json: {len(renbtc_minters_notin_final)}")
    