// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	chain ChainContext // Chain context interface
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(chain ChainContext) *StateProcessor {
	return &StateProcessor{
		chain: chain,
	}
}

// chainConfig returns the chain configuration.
func (p *StateProcessor) chainConfig() *params.ChainConfig {
	return p.chain.Config()
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
/*
Process runs all transactions in a block following Ethereum rules and updates the state accordingly.

- It starts by loading the chain configuration and initializing gas tracking and receipts storage.
- If the block is the special DAO fork block, apply the DAO hard fork changes (e.g., refunding DAO balances).
- It creates a signer specific to the block’s fork rules to verify transactions correctly.
- A state wrapper with optional tracing hooks is prepared for monitoring execution.
- The EVM context and instance are created with the current block and chain settings.
- If the block contains special beacon root info, it is processed by a system call.
- For recent forks like Prague and Verkle, parent block hash is stored as required by new consensus rules.

Then, it processes each transaction in the block one by one:
- Converts the transaction into a message format for the EVM.
- Sets the current transaction context on the state.
- Applies the transaction using the EVM, updating state and accumulating gas used.
- Collects receipts and logs for each transaction.

If the Prague fork is active:
- Parses deposit logs from transactions and adds them to the requests list.
- Processes withdrawal and consolidation queues via system contract calls, updating the requests.

Finally:
- Calls the consensus engine’s Finalize method to apply final block changes like miner rewards.
- Returns the combined results: receipts, logs, any special requests, and total gas used.

This function ensures all Ethereum protocol rules and fork-specific features are applied during block execution.
*/
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (*ProcessResult, error) {
	var (
		// Load the chain configuration for using fork-specific rules
		config = p.chainConfig()
		// Prepare to collect receipts
		receipts types.Receipts
		// Track total gas used by the block
		usedGas = new(uint64)
		// Get block header, hash, and number for reference
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		// Prepare to collect  logs of transactions
		allLogs []*types.Log
		// Initialize GasPool to track gas limit for block execution
		gp = new(GasPool).AddGas(block.GasLimit())
	)

	// Mutate the block and state according to any hard-fork specs
	// If this block matches the DAO fork block, apply the DAO Hard Fork balance changes
	if config.DAOForkSupport && config.DAOForkBlock != nil && config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	var (
		context vm.BlockContext
		// MakeSigner returns a Signer based on the given chain config and block number.
		// Create a signer to verify transactions, based on the block number and fork rules
		signer = types.MakeSigner(config, header.Number, header.Time)
	)

	// Apply pre-execution system calls.
	// Wrap statedb with tracing hooks if configured, for debugging and monitoring
	var tracingStateDB = vm.StateDB(statedb)
	if hooks := cfg.Tracer; hooks != nil {
		tracingStateDB = state.NewHookedState(statedb, hooks)
	}
	// Create the EVM execution context for this block
	context = NewEVMBlockContext(header, p.chain, nil)
	// Instantiate a new EVM with the context, state DB, chain config, and VM config
	evm := vm.NewEVM(context, tracingStateDB, config, cfg)

	// Process beacon block root info if present (for consensus-specific logic)
	if beaconRoot := block.BeaconRoot(); beaconRoot != nil {
		ProcessBeaconBlockRoot(*beaconRoot, evm)
	}
	// For Prague or Verkle forks, store parent block hash as required by updated consensus rules
	if config.IsPrague(block.Number(), block.Time()) || config.IsVerkle(block.Number(), block.Time()) {
		ProcessParentBlockHash(block.ParentHash(), evm)
	}

	// Iterate over and process the individual transactions
	// Loop through each transaction in the block for processing
	for i, tx := range block.Transactions() {
		// Convert transaction format to EVM message format, using signer and block base fee
		msg, err := TransactionToMessage(tx, signer, header.BaseFee)
		if err != nil {
			return nil, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		// Set the current transaction context (hash and index) on the stateDB
		// SetTxContext sets the current transaction hash and index which are
		// used when the EVM emits new state logs. It should be invoked before
		// transaction execution.
		statedb.SetTxContext(tx.Hash(), i)

		// Apply the transaction using the EVM, gas pool, block info, and accumulating used gas
		receipt, err := ApplyTransactionWithEVM(msg, gp, statedb, blockNumber, blockHash, context.Time, tx, usedGas, evm)
		if err != nil {
			return nil, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		// Collect the receipt and logs for this transaction
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	// Read requests if Prague is enabled.
	// Prepare to collect any special "requests" if Prague upgrade rules apply
	var requests [][]byte
	if config.IsPrague(block.Number(), block.Time()) {
		requests = [][]byte{}
		// EIP-6110
		// Parse deposit logs (EIP-6110) from receipts' logs
		/*
			- This EIP integrates validator deposits directly into the Ethereum Execution Layer blocks, eliminating
			the previous deposit voting mechanism in the Consensus Layer.
			- It streamlines deposit processing by including validator deposits as a list of deposit operations in the
			execution layer, enhancing security, reducing delays, and simplifying client software design.​
		*/
		if err := ParseDepositLogs(&requests, allLogs, config); err != nil {
			return nil, fmt.Errorf("failed to parse deposit logs: %w", err)
		}
		// EIP-7002
		// Process withdrawal queue contract (EIP-7002)
		/*
			- This EIP allows validators to trigger withdrawals and exits using their execution
			  layer withdrawal credentials.
			- It enables validators to submit withdrawal requests through a queue system in a
			contract, bypassing the need for active signing keys to initiate exits.
			- It introduces a queue with rate-limiting and fee adjustments to handle withdrawal
			requests systematically, improving validator autonomy and security.
		*/
		if err := ProcessWithdrawalQueue(&requests, evm); err != nil {
			return nil, fmt.Errorf("failed to process withdrawal queue: %w", err)
		}
		// EIP-7251
		// Process consolidation queue contract (EIP-7251)
		/*
			- Processes the consolidation queue contract.

			- This EIP increases the maximum effective staking balance per validator beyond the previous
			32 ETH limit (potentially up to 2048 ETH).

			- It allows large validators to consolidate stakes into fewer accounts, reducing the number
			 of validators and improving Ethereum's scalability and efficiency while maintaining decentralization.

			- Introduces protocol mechanisms for merging balances via consolidation requests
			 processed through a queue contract
		*/
		if err := ProcessConsolidationQueue(&requests, evm); err != nil {
			return nil, fmt.Errorf("failed to process consolidation queue: %w", err)
		}
	}

	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	// Call consensus engine to finalize the block,
	// applying any mining rewards, uncle rewards, or other state changes
	p.chain.Engine().Finalize(p.chain, header, tracingStateDB, block.Body())

	// Return the final results of processing the block
	return &ProcessResult{
		Receipts: receipts,
		Requests: requests,
		Logs:     allLogs,
		GasUsed:  *usedGas,
	}, nil
}

// ApplyTransactionWithEVM attempts to apply a transaction to the given state database
// and uses the input parameters for its environment similar to ApplyTransaction. However,
// this method takes an already created EVM instance as input.
func ApplyTransactionWithEVM(msg *Message, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, blockTime uint64, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (receipt *types.Receipt, err error) {
	// If tracing hooks are set (for debugging or monitoring), notify the start of this transaction execution.
	if hooks := evm.Config.Tracer; hooks != nil {
		if hooks.OnTxStart != nil {
			hooks.OnTxStart(evm.GetVMContext(), tx, msg.From) // Signal transaction start
		}
		// Arrange to notify when this transaction finishes, including the receipt and error status.
		if hooks.OnTxEnd != nil {
			defer func() { hooks.OnTxEnd(receipt, err) }()
		}
	}
	// Apply the transaction to the current state (included in the env).
	/*
		// ApplyMessage computes the new state by applying the given message
		// against the old state within the environment.
		//
		// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
		// the gas used (which includes gas refunds) and an error if it failed. An error always
		// indicates a core error meaning that the message would always fail for that particular
		// state and would never be accepted within a block.
	*/
	result, err := ApplyMessage(evm, msg, gp) // This executes the contract logic or transfer
	if err != nil {
		return nil, err // Return if something went wrong during execution
	}
	// Update the state with pending changes.
	// Update the blockchain state according to the rules of the current protocol.
	var root []byte
	if evm.ChainConfig().IsByzantium(blockNumber) {
		// For blocks after the Byzantium fork, finalize the state with intermediate changes.
		evm.StateDB.Finalise(true)
	} else {
		// For earlier blocks, compute the intermediate root of state trie.
		root = statedb.IntermediateRoot(evm.ChainConfig().IsEIP158(blockNumber)).Bytes()
	}
	// Add the gas used by this transaction to the total gas counter.
	*usedGas += result.UsedGas

	// Merge the tx-local access event into the "block-local" one, in order to collect
	// all values, so that the witness can be built.
	/* If the system uses the newer Verkle trie structure, merge this transaction's access events
	   with the block-level collection to later build proofs efficiently. */
	if statedb.Database().TrieDB().IsVerkle() {
		statedb.AccessEvents().Merge(evm.AccessEvents)
	}
	// Create and return a receipt summarizing the transaction outcome and state changes.
	return MakeReceipt(evm, result, statedb, blockNumber, blockHash, blockTime, tx, *usedGas, root), nil
}

// MakeReceipt generates the receipt object for a transaction given its execution result.
func MakeReceipt(evm *vm.EVM, result *ExecutionResult, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, blockTime uint64, tx *types.Transaction, usedGas uint64, root []byte) *types.Receipt {
	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	if tx.Type() == types.BlobTxType {
		receipt.BlobGasUsed = uint64(len(tx.BlobHashes()) * params.BlobTxBlobGasPerBlob)
		receipt.BlobGasPrice = evm.Context.BlobBaseFee
	}

	// If the transaction created a contract, store the creation address in the receipt.
	if tx.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash, blockTime)
	receipt.Bloom = types.CreateBloom(receipt)
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(evm *vm.EVM, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64) (*types.Receipt, error) {
	msg, err := TransactionToMessage(tx, types.MakeSigner(evm.ChainConfig(), header.Number, header.Time), header.BaseFee)
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	return ApplyTransactionWithEVM(msg, gp, statedb, header.Number, header.Hash(), header.Time, tx, usedGas, evm)
}

// ProcessBeaconBlockRoot applies the EIP-4788 system call to the beacon block root
// contract. This method is exported to be used in tests.
func ProcessBeaconBlockRoot(beaconRoot common.Hash, evm *vm.EVM) {
	if tracer := evm.Config.Tracer; tracer != nil {
		onSystemCallStart(tracer, evm.GetVMContext())
		if tracer.OnSystemCallEnd != nil {
			defer tracer.OnSystemCallEnd()
		}
	}
	msg := &Message{
		From:      params.SystemAddress,
		GasLimit:  30_000_000,
		GasPrice:  common.Big0,
		GasFeeCap: common.Big0,
		GasTipCap: common.Big0,
		To:        &params.BeaconRootsAddress,
		Data:      beaconRoot[:],
	}
	evm.SetTxContext(NewEVMTxContext(msg))
	evm.StateDB.AddAddressToAccessList(params.BeaconRootsAddress)
	_, _, _ = evm.Call(msg.From, *msg.To, msg.Data, 30_000_000, common.U2560)
	evm.StateDB.Finalise(true)
}

// ProcessParentBlockHash stores the parent block hash in the history storage contract
// as per EIP-2935/7709.
func ProcessParentBlockHash(prevHash common.Hash, evm *vm.EVM) {
	if tracer := evm.Config.Tracer; tracer != nil {
		onSystemCallStart(tracer, evm.GetVMContext())
		if tracer.OnSystemCallEnd != nil {
			defer tracer.OnSystemCallEnd()
		}
	}
	msg := &Message{
		From:      params.SystemAddress,
		GasLimit:  30_000_000,
		GasPrice:  common.Big0,
		GasFeeCap: common.Big0,
		GasTipCap: common.Big0,
		To:        &params.HistoryStorageAddress,
		Data:      prevHash.Bytes(),
	}
	evm.SetTxContext(NewEVMTxContext(msg))
	evm.StateDB.AddAddressToAccessList(params.HistoryStorageAddress)
	_, _, err := evm.Call(msg.From, *msg.To, msg.Data, 30_000_000, common.U2560)
	if err != nil {
		panic(err)
	}
	if evm.StateDB.AccessEvents() != nil {
		evm.StateDB.AccessEvents().Merge(evm.AccessEvents)
	}
	evm.StateDB.Finalise(true)
}

// ProcessWithdrawalQueue calls the EIP-7002 withdrawal queue contract.
// It returns the opaque request data returned by the contract.
func ProcessWithdrawalQueue(requests *[][]byte, evm *vm.EVM) error {
	return processRequestsSystemCall(requests, evm, 0x01, params.WithdrawalQueueAddress)
}

// ProcessConsolidationQueue calls the EIP-7251 consolidation queue contract.
// It returns the opaque request data returned by the contract.
func ProcessConsolidationQueue(requests *[][]byte, evm *vm.EVM) error {
	return processRequestsSystemCall(requests, evm, 0x02, params.ConsolidationQueueAddress)
}

func processRequestsSystemCall(requests *[][]byte, evm *vm.EVM, requestType byte, addr common.Address) error {
	if tracer := evm.Config.Tracer; tracer != nil {
		onSystemCallStart(tracer, evm.GetVMContext())
		if tracer.OnSystemCallEnd != nil {
			defer tracer.OnSystemCallEnd()
		}
	}
	msg := &Message{
		From:      params.SystemAddress,
		GasLimit:  30_000_000,
		GasPrice:  common.Big0,
		GasFeeCap: common.Big0,
		GasTipCap: common.Big0,
		To:        &addr,
	}
	evm.SetTxContext(NewEVMTxContext(msg))
	evm.StateDB.AddAddressToAccessList(addr)
	ret, _, err := evm.Call(msg.From, *msg.To, msg.Data, 30_000_000, common.U2560)
	evm.StateDB.Finalise(true)
	if err != nil {
		return fmt.Errorf("system call failed to execute: %v", err)
	}
	if len(ret) == 0 {
		return nil // skip empty output
	}
	// Append prefixed requestsData to the requests list.
	requestsData := make([]byte, len(ret)+1)
	requestsData[0] = requestType
	copy(requestsData[1:], ret)
	*requests = append(*requests, requestsData)
	return nil
}

var depositTopic = common.HexToHash("0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5")

// ParseDepositLogs extracts the EIP-6110 deposit values from logs emitted by
// BeaconDepositContract.
func ParseDepositLogs(requests *[][]byte, logs []*types.Log, config *params.ChainConfig) error {
	deposits := make([]byte, 1) // note: first byte is 0x00 (== deposit request type)
	for _, log := range logs {
		if log.Address == config.DepositContractAddress && len(log.Topics) > 0 && log.Topics[0] == depositTopic {
			request, err := types.DepositLogToRequest(log.Data)
			if err != nil {
				return fmt.Errorf("unable to parse deposit data: %v", err)
			}
			deposits = append(deposits, request...)
		}
	}
	if len(deposits) > 1 {
		*requests = append(*requests, deposits)
	}
	return nil
}

func onSystemCallStart(tracer *tracing.Hooks, ctx *tracing.VMContext) {
	if tracer.OnSystemCallStartV2 != nil {
		tracer.OnSystemCallStartV2(ctx)
	} else if tracer.OnSystemCallStart != nil {
		tracer.OnSystemCallStart()
	}
}
