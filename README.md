# Voting

## NodeJS demo

```
npm install
cd demo
node demo-node
```

`circuit.json`, `proving_key.json` and `verification_key.json` will be generated.

## Browser demo

With the JSON files generated on `./demo`

```
npx parcel index.html
```

Open http://localhost:1234 and open the browser's console to see the progress.

## Compressing JSON data

If you want to serialize and compress the JSON artifacts, feel free to check out the [json-compression](https://github.com/adriamb/voting/tree/json-compression/demo) branch

## Note:

Before `circomlib` is updated, the following changes need to be applied on version `0.0.5`:

* Importing web3-utils and replacing the appearences of `Web3.utils` by Web3Utils on `.../circomlib/src/mimc7.js`
* Adding `exports.babyJub = require("./src/babyjub");` on `.../circomlib/index.js`
* Adding `exports.pruneBuffer = pruneBuffer;` on `.../circomlib/src/eddsa.js`

See PR https://github.com/iden3/circomlib/pull/4
