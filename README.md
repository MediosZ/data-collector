# Web3 Data Collector

## Usage 

### Setup QuickNode

Add Quick Node endpoint into `.env`.

```
QUICK_NODE=wss://XXXX
```

### Get the balance of an account

```bash
cargo r -- get_balance <address>
```

### Get the transactions of a block

```bash
cargo r -- get_transactions block_id
```