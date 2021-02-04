# Debugtool
This repo is a command-line tool that provides basic functionalities for interacting with the [Incognito](https://we.incognito.org) blockchain. Developers with deep knowledge of the Incognito network are warmly welcomed to modify the source code to favor their needs.
 
## Usage
```bash
cd main
go get -v
go run *.go
```

## Functions
### Environment-related
1. `port`
    - Description: switch the port of the current environment
    - How to use: `port PORT_NUMBER` 
    - Examples: `port 9334`

1. `inittestnet`
    - Description: init the param to the testnet environment
    - How to use: `inittestnet`
    
1. `initmainnet`
    - Description: init the param to the mainnet environment
    - How to use: `initmainnet`

1. `initdevnet`
    - Description: init the param to the devnet environment
    - How to use: `inittestnet [PORT_NUMBER]`
        + PORT_NUMBER (optional): the port number , default is `8334`
    - Examples:
        + `initdevnet`
        + `initdevnet 3334`

1. `initlocal`
    - Description: init the param to the local node
    - How to use: `initlocal [PORT_NUMBER]`
        + PORT_NUMBER (optional): the port number , default is `9334`
    - Examples:
        + `initlocal`
        + `initlocal 9338`

### TXO-related
1. `outcoin`
    - Description: get the list of output coins (TXOs) for a given user
    - How to use: `outcoin PRIVATE_KEY [TOKEN_ID]`
        + PRIVATE_KEY: the private key of the user
        + TOKEN_ID (optional): the tokenID of the needed coins, default is PRV
    - Examples:
        + `outcoin 0`
        + `outcoin 0 ffd8d42dc40a8d166ea4848baf8b5f6e912ad79875f4373070b59392b1756c8f`
        + `outcoin 112t8rnZDRztVgPjbYQiXS7mJgaTzn66NvHD7Vus2SrhSAY611AzADsPFzKjKQCKWTgbkgYrCPo9atvSMoCf9KT23Sc7Js9RKhzbNJkxpJU6`
        + `outcoin 112t8rnZDRztVgPjbYQiXS7mJgaTzn66NvHD7Vus2SrhSAY611AzADsPFzKjKQCKWTgbkgYrCPo9atvSMoCf9KT23Sc7Js9RKhzbNJkxpJU6 ETH`  
1. `uot`
    - Description: get the list of unspent output coin (UTXOs) of a given user
    - How to use: `uot PRIVATE_KEY [TOKEN_ID]`
        + PRIVATE_KEY: the private key of the user
        + TOKEN_ID (optional): the tokenID of the needed coins, default is `PRV`
    - Examples:
        + `uot 0`
        + `uot 0 ffd8d42dc40a8d166ea4848baf8b5f6e912ad79875f4373070b59392b1756c8f`
        + `uot 112t8rnZDRztVgPjbYQiXS7mJgaTzn66NvHD7Vus2SrhSAY611AzADsPFzKjKQCKWTgbkgYrCPo9atvSMoCf9KT23Sc7Js9RKhzbNJkxpJU6`
        + `uot 112t8rnZDRztVgPjbYQiXS7mJgaTzn66NvHD7Vus2SrhSAY611AzADsPFzKjKQCKWTgbkgYrCPo9atvSMoCf9KT23Sc7Js9RKhzbNJkxpJU6 ETH`
         
1. `balance`
    - Description: get the balance of a given user
    - How to use: `balance PRIVATE_KEY [TOKEN_ID]`
        + PRIVATE_KEY: the private key of the user
        + TOKEN_ID (optional): the tokenID of the needed coins, default is PRV
    - Examples:
        + `balance 0`
        + `balance 0 ffd8d42dc40a8d166ea4848baf8b5f6e912ad79875f4373070b59392b1756c8f`
        + `balance 112t8rnZDRztVgPjbYQiXS7mJgaTzn66NvHD7Vus2SrhSAY611AzADsPFzKjKQCKWTgbkgYrCPo9atvSMoCf9KT23Sc7Js9RKhzbNJkxpJU6`
        + `balance 112t8rnZDRztVgPjbYQiXS7mJgaTzn66NvHD7Vus2SrhSAY611AzADsPFzKjKQCKWTgbkgYrCPo9atvSMoCf9KT23Sc7Js9RKhzbNJkxpJU6 ETH`

### Transaction-related
1. `transfer`
    - Description: perform a PRV transferring transaction
    - How to use: `transfer PRIVATE_KEY ADDRESS AMOUNT [TX_VERSION]`
        + PRIVATE_KEY: the private key of the sender
        + ADDRESS: the receiver address
        + AMOUNT: the transacted amount (unit: nano)
        + TX_VERSION (optional): the version of the transaction (`1` or `2`), the default value is `-1` (try either of the version if possible)
    - Examples:
        + `transfer 0 1 1000000`
        + `transfer 0 1 1000000 1`
        + `transfer 112t8rnZDRztVgPjbYQiXS7mJgaTzn66NvHD7Vus2SrhSAY611AzADsPFzKjKQCKWTgbkgYrCPo9atvSMoCf9KT23Sc7Js9RKhzbNJkxpJU6 12S5Lrs1XeQLbqN4ySyKtjAjd2d7sBP2tjFijzmp6avrrkQCNFMpkXm3FPzj2Wcu2ZNqJEmh9JriVuRErVwhuQnLmWSaggobEWsBEci 1000000`

1. `transfertoken`
    - Description: perform a token transferring transaction
    - How to use: `transfertoken PRIVATE_KEY ADDRESS TOKEN_ID AMOUNT [TX_VERSION]`
        + PRIVATE_KEY: the private key of the sender
        + ADDRESS: the receiver address
        + TOKEN_ID: the id of the transacted asset
        + AMOUNT: the transacted amount (unit: nano)
        + TX_VERSION (optional): the version of the transaction (`1` or `2`), the default value is `-1` (try either of the version if possible)
    - Examples:
        + `transfertoken 0 1 ETH 1000000`
        + `transfertoken 0 1 ffd8d42dc40a8d166ea4848baf8b5f6e912ad79875f4373070b59392b1756c8f 1000000 1`
        + `transfertoken 112t8rnZDRztVgPjbYQiXS7mJgaTzn66NvHD7Vus2SrhSAY611AzADsPFzKjKQCKWTgbkgYrCPo9atvSMoCf9KT23Sc7Js9RKhzbNJkxpJU6 12S5Lrs1XeQLbqN4ySyKtjAjd2d7sBP2tjFijzmp6avrrkQCNFMpkXm3FPzj2Wcu2ZNqJEmh9JriVuRErVwhuQnLmWSaggobEWsBEci ffd8d42dc40a8d166ea4848baf8b5f6e912ad79875f4373070b59392b1756c8f 1000000`

1. `convert`
    - Description: convert all UTXOs version 1 to a UTXO version 2
    - How to use: `convert PRIVATE_KEY [TOKEN_ID]`
        + PRIVATE_KEY: the private key of the sender
        + TOKEN_ID (optional): the id of the transacted asset, default is `PRV`
    - Examples:
        + `convert 0`
        + `convert 0 ETH`
        + `convert 112t8rnZDRztVgPjbYQiXS7mJgaTzn66NvHD7Vus2SrhSAY611AzADsPFzKjKQCKWTgbkgYrCPo9atvSMoCf9KT23Sc7Js9RKhzbNJkxpJU6 ffd8d42dc40a8d166ea4848baf8b5f6e912ad79875f4373070b59392b1756c8f`    

### pDEX-related
1. `pdetradeprv`
    - Description: perform a PRV trading transaction
    - How to use: `pdetradeprv PRIVATE_KEY TOKEN_TO_BUY AMOUNT`
        + PRIVATE_KEY: the private key of the sender
        + TOKEN_TO_BUY: the id of the token being traded to
        + AMOUNT: the PRV selling amount
    - Examples:
        + `pdetradeprv 0 ETH 100000000000`
        + `pdetradeprv 0 ffd8d42dc40a8d166ea4848baf8b5f6e912ad79875f4373070b59392b1756c8f 100000000000`
        + `pdetradeprv 112t8rnZDRztVgPjbYQiXS7mJgaTzn66NvHD7Vus2SrhSAY611AzADsPFzKjKQCKWTgbkgYrCPo9atvSMoCf9KT23Sc7Js9RKhzbNJkxpJU6 ffd8d42dc40a8d166ea4848baf8b5f6e912ad79875f4373070b59392b1756c8f 100000000000`

1. `pdetradetoken`
    - Description: perform a token trading transaction
    - How to use: `pdetradetoken PRIVATE_KEY TOKEN_TO_SELL TOKEN_TO_BUY AMOUNT`
        + PRIVATE_KEY: the private key of the sender
        + TOKEN_TO_SELL: the id of the token being traded from
        + TOKEN_TO_BUY: the id of the token being traded to
        + AMOUNT: the selling amount
    - Examples:
        + `pdetradeprv 0 ETH PRV 100000000000`
        + `pdetradeprv 0 ETH USDT 100000000000`

1. `pdecontribute`
    - Description: contribute PRV or tokens to the current pDEX
    - How to use: `pdecontribute PRIVATE_KEY AMOUNT [TOKEN_ID]`
        + PRIVATE_KEY: the private key of the sender
        + AMOUNT: the contributed amount
        + TOKEN_ID (optional): the id of the transacted asset, default is `PRV`
    - Examples:
        + `pdecontribute 0 100000000000`
        + `pdecontribute 0 100000000000 ETH`

1. `pdewithdraw`
    - Description: contribute PRV or tokens to the current pDEX
    - How to use: `pdewithdraw PRIVATE_KEY TOKEN_ID1 TOKEN_ID2 SHARED_AMOUNT`
        + PRIVATE_KEY: the private key of the sender
        + TOKEN_ID1: the id of the first asset (any order is acceptable)
        + TOKEN_ID2: the id of the second asset (any order is acceptable)
        + SHARED_AMOUNT: the shared amount in need of withdrawing
    - Examples:
        + `pdewithdraw 0 PRV ETH 100000`
        + `pdewithdraw 0 ETH PRV 100000`

1. `pdestate`
    - Description: get the pDEX state of the blockchain
    - How to use: `pdestate [BEACON_HEIGHT]`
        + BEACON_HEIGHT: the beacon height at which you want to retrieve the pDEX state, default is the latest beacon height
    - Examples:
        + `pdestate`
        + `pdestate 10000`

1. `poolpairs`
    - Description: get all the pool pairs on the pDEX
    - How to use: `poolpairs [BEACON_HEIGHT]`
        + BEACON_HEIGHT: the beacon height at which you want to retrieve pool pairs, default is the latest beacon height
    - Examples:
        + `poolpairs`
        + `poolpairs 10000`

1. `pool`
    - Description: get the detail of a pool on the pDEX
    - How to use: `pool TOKEN_ID1 TOKEN_ID2 [BEACON_HEIGHT]`
        + TOKEN_ID1: the id of the first asset (any order is acceptable)
        + TOKEN_ID2: the id of the second asset (any order is acceptable)
        + BEACON_HEIGHT: the beacon height at which you want to retrieve the pool detail, default is the latest beacon height
    - Examples:
        + `pool PRV ETH`
        + `poll PRV ETH 10000`

1. `checkprice`
    - Description: check the current trading value
    - How to use: `checkprice TOKEN_TO_SELL TOKEN_TO_BUY AMOUNT`
        + TOKEN_TO_SELL: the id of the token being traded from
        + TOKEN_TO_BUY: the id of the token being traded to
        + AMOUNT: the selling amount, notice that different amounts result in different trading rates since the pDEX is using UniSwap
    - Examples:
        + `checkprice PRV ETH 100000`
        + `checkprice ETH BTC 100000`

### Staking-related
1. `staking`
    - Description: perform a staking transaction
    - How to use: `staking PRIVATE_KEY [IS_AUTO_RESTAKING]`
        + PRIVATE_KEY: the private key of the sender
        + IS_AUTO_RESTAKING (optional): indicate whether you want to automatically re-stake after swapped, default is `true`
    - Examples:
        + `staking 0`
        + `staking 0 false`
        
1. `unstaking`
    - Description: perform an un-staking transaction
    - How to use: `unstaking PRIVATE_KEY [ADDR]`
        + PRIVATE_KEY: the private key of the sender
        + ADDR (optional): the committee candidate payment address supplied when staking, default is the address associated with the `PRIVATE_KEY`
    - Examples:
        + `unstaking 0`
        + `unstaking 0 12S5Lrs1XeQLbqN4ySyKtjAjd2d7sBP2tjFijzmp6avrrkQCNFMpkXm3FPzj2Wcu2ZNqJEmh9JriVuRErVwhuQnLmWSaggobEWsBEci`
        
1. `reward`
    - Description: withdraw the reward of a given user
    - How to use: `reward PRIVATE_KEY [ADDR]`
        + PRIVATE_KEY: the private key of the sender
        + ADDR (optional): the reward-receiving payment address supplied when staking, default is the address associated with the `PRIVATE_KEY`
    - Examples:
        + `reward 0`
        + `reward 0 12S5Lrs1XeQLbqN4ySyKtjAjd2d7sBP2tjFijzmp6avrrkQCNFMpkXm3FPzj2Wcu2ZNqJEmh9JriVuRErVwhuQnLmWSaggobEWsBEci`

1. `listreward`
    - Description: list the detail of the current reward on the blockchain
    - How to use: `listreward`

### Blockchain-related
1. `info`
    - Description: get the current info of the blockchain
    - How to use: `info`

1. `beaconstate`
    - Description: get the current beacon state detail of the blockchain
    - How to use: `beaconstate`

1. `shardstate`
    - Description: get the current shard state detail of the blockchain
    - How to use: `shardstate SHARD_ID`
        + SHARD_ID: the shard id number
    - Examples:
        + `shardstate 0`
        + `shardstate 1`

1. `bestblock`
    - Description: get the latest blocks (beacon + shard blocks) of the blockchain
    - How to use: `bestblock`
    
1. `mempool`
    - Description: get the current mempool info of the blockchain node
    - How to use: `mempool`
    
1. `txhash`
    - Description: get the detail of a transaction
    - How to use: `txhash TX_HASH`
        + TX_HASH: the transaction id
    - Examples:
        + `txhash 80e96c92032505a12b20fe7b15b9bf379bac903dbbc2ef4063f84d38b7f4cfc1`
        
1. `listtoken`
    - Description: list all tokens currently present in the blockchain environment
    - How to use: `listtoken`  

### Key-related
1. `payment`
    - Description: get the payment address from the private key
    - How to use: `payment PRIVATE_KEY`
        + PRIVATE_KEY: the private key of the user
    - Examples:
        + `payment 0`
        + `payment 112t8rnZDRztVgPjbYQiXS7mJgaTzn66NvHD7Vus2SrhSAY611AzADsPFzKjKQCKWTgbkgYrCPo9atvSMoCf9KT23Sc7Js9RKhzbNJkxpJU6`

1. `public`
    - Description: get the public key from the private key
    - How to use: `public PRIVATE_KEY`
        + PRIVATE_KEY: the private key of the user
    - Examples:
        + `public 0`
        + `public 112t8rnZDRztVgPjbYQiXS7mJgaTzn66NvHD7Vus2SrhSAY611AzADsPFzKjKQCKWTgbkgYrCPo9atvSMoCf9KT23Sc7Js9RKhzbNJkxpJU6`

1. `cmkey`
    - Description: generate a committee key from a private key
    - How to use: `cmkey PRIVATE_KEY`
        + PRIVATE_KEY: the private key of the user
    - Examples:
        + `cmkey 0`
        + `cmkey 112t8rnZDRztVgPjbYQiXS7mJgaTzn66NvHD7Vus2SrhSAY611AzADsPFzKjKQCKWTgbkgYrCPo9atvSMoCf9KT23Sc7Js9RKhzbNJkxpJU6`
        

## Notes
1. To use the old payment address, change the variable `b58Version` in the function `Base58CheckSerialize` to `0`.