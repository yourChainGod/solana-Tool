package main

import (
	"context"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gagliardetto/solana-go/rpc/ws"
	"github.com/tidwall/gjson"
)

type Config struct {
	rpcClient    *RPCClient
	wsClient     *ws.Client
	PrivateKey   string
	Recipients   []string
	Amount       float64
	Batch        int
	CollectBatch int
}

var logger *log.Logger

type RPCClient struct {
	*rpc.Client
}

type levelStyle struct {
	text  string
	color string
}

type keyValueStyle struct {
	keyColor   string
	valueColor string
}

const (
	defaultRetryCount     = 50
	defaultRetryDelay     = 2 * time.Second
	defaultConfirmTimeout = 2 * time.Minute
	maxConcurrentTx       = 9
	lamportsPerSol        = 1e9
)

// 配置项验证错误
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("配置错误 [%s]: %s", e.Field, e.Message)
}

// 初始化日志
func initLogger() *log.Logger {
	logColors := struct {
		Error     string
		Info      string
		Success   string
		Orange    string
		Purple    string
		SeaGreen  string
		Gold      string
		Pink      string
		Cyan      string
		LightBlue string
	}{
		Error:     "#FF4D4D", // 错误红
		Info:      "#4D94FF", // 信息蓝
		Success:   "#00CC66", // 成功绿
		Orange:    "#FFA500", // 橙色
		Purple:    "#9370DB", // 紫色
		SeaGreen:  "#20B2AA", // 浅绿宝石色
		Gold:      "#FFD700", // 金色
		Pink:      "#FF69B4", // 粉色
		Cyan:      "#00CED1", // 深青色
		LightBlue: "#66CCFF", // 浅蓝色
	}

	logLevels := map[log.Level]levelStyle{
		log.ErrorLevel: {"错误", logColors.Error},
		log.InfoLevel:  {"信息", logColors.Info},
		log.WarnLevel:  {"成功", logColors.Success},
	}

	logKeyStyles := map[string]keyValueStyle{
		"错误":   {logColors.Error, ""},
		"批次":   {logColors.Orange, logColors.Purple},
		"状态":   {logColors.SeaGreen, logColors.Gold},
		"交易ID": {logColors.Pink, logColors.Cyan},
	}
	// 创建日志实例
	logger := log.NewWithOptions(os.Stderr, log.Options{
		ReportCaller:    false,
		ReportTimestamp: true,
		TimeFormat:      "15:04:05",
		Level:           log.InfoLevel,
		Prefix:          "hdd.cm",
	})

	// 创建样式
	styles := log.DefaultStyles()

	// 设置日志级别样式
	for level, style := range logLevels {
		styles.Levels[level] = lipgloss.NewStyle().
			SetString(style.text).
			Padding(0, 1, 0, 1).
			Foreground(lipgloss.Color(style.color))
	}

	// 设置键值样式
	for key, style := range logKeyStyles {
		styles.Keys[key] = lipgloss.NewStyle().
			Foreground(lipgloss.Color(style.keyColor))

		if style.valueColor != "" {
			styles.Values[key] = lipgloss.NewStyle().
				Foreground(lipgloss.Color(style.valueColor))
		} else {
			styles.Values[key] = lipgloss.NewStyle()
		}
	}

	// 设置默认键样式
	styles.Key = lipgloss.NewStyle().
		Foreground(lipgloss.Color(logColors.LightBlue))

	logger.SetStyles(styles)
	os.Setenv("TZ", "Asia/Jakarta")

	return logger
}

// 验证配置项
func validateConfig(config map[string]string) error {
	required := []string{"privateKey", "rpc", "ws", "amount", "batch", "collectBatch"}
	for _, field := range required {
		if _, ok := config[field]; !ok {
			return &ConfigError{field, "必填项不能为空"}
		}
	}

	// 验证数值范围
	amount, err := strconv.ParseFloat(config["amount"], 64)
	if err != nil {
		return &ConfigError{"amount", "必须是有效的数字"}
	}
	if amount <= 0 {
		return &ConfigError{"amount", "必须大于0"}
	}

	batch, err := strconv.Atoi(config["batch"])
	if err != nil {
		return &ConfigError{"batch", "必须是有效的整数"}
	}
	if batch <= 0 || batch > 100 {
		return &ConfigError{"batch", "必须在1-100之间"}
	}

	collectBatch, err := strconv.Atoi(config["collectBatch"])
	if err != nil {
		return &ConfigError{"collectBatch", "必须是有效的整数"}
	}
	if collectBatch <= 0 || collectBatch > 100 {
		return &ConfigError{"collectBatch", "必须在1-100之间"}
	}

	// 验证私钥格式
	if len(config["privateKey"]) < 64 {
		return &ConfigError{"privateKey", "私钥格式无效"}
	}

	// 验证RPC地址格式
	if !strings.HasPrefix(config["rpc"], "http") {
		return &ConfigError{"rpc", "必须是有效的HTTP(S)地址"}
	}
	if !strings.HasPrefix(config["ws"], "ws") {
		return &ConfigError{"ws", "必须是有效的WebSocket地址"}
	}

	return nil
}

func NewConfig(rpcUrl, wsUrl, privateKey string, recipients []string, amount float64, batch int) *Config {
	wsClient, err := ws.Connect(context.Background(), wsUrl)
	if err != nil {
		logger.Error("连接WebSocket", "状态", "连接失败!", "错误", err)
		return nil
	}

	return &Config{
		rpcClient:  &RPCClient{rpc.New(rpcUrl)},
		wsClient:   wsClient,
		PrivateKey: privateKey,
		Recipients: recipients,
		Amount:     amount,
		Batch:      batch,
	}
}

// 通用RPC调用包装函数
func (r *RPCClient) rpcCall(ctx context.Context, call func() (interface{}, error)) (interface{}, error) {
	result, err := call()
	if err != nil {
		if strings.Contains(err.Error(), "exceeded limit for rpc") {
			time.Sleep(1 * time.Second)
			return r.rpcCall(ctx, call)
		}
		return result, err
	}
	return result, nil
}

func (r *RPCClient) NewGetLatestBlockhash(ctx context.Context, commitment rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	result, err := r.rpcCall(ctx, func() (interface{}, error) {
		return r.Client.GetLatestBlockhash(ctx, commitment)
	})
	if err != nil {
		return nil, err
	}
	return result.(*rpc.GetLatestBlockhashResult), nil
}

func (r *RPCClient) NewGetBalance(ctx context.Context, address solana.PublicKey, commitment rpc.CommitmentType) (*rpc.GetBalanceResult, error) {
	result, err := r.rpcCall(ctx, func() (interface{}, error) {
		return r.Client.GetBalance(ctx, address, commitment)
	})
	if err != nil {
		return nil, err
	}
	return result.(*rpc.GetBalanceResult), nil
}

func (r *RPCClient) NewGetTokenAccountsByOwner(ctx context.Context, owner solana.PublicKey, conf *rpc.GetTokenAccountsConfig, opts *rpc.GetTokenAccountsOpts) (*rpc.GetTokenAccountsResult, error) {
	result, err := r.rpcCall(ctx, func() (interface{}, error) {
		return r.Client.GetTokenAccountsByOwner(ctx, owner, conf, opts)
	})
	if err != nil {
		return nil, err
	}
	return result.(*rpc.GetTokenAccountsResult), nil
}

func (r *RPCClient) NewGetTokenAccountBalance(ctx context.Context, address solana.PublicKey, commitment rpc.CommitmentType) (*rpc.GetTokenAccountBalanceResult, error) {
	result, err := r.rpcCall(ctx, func() (interface{}, error) {
		return r.Client.GetTokenAccountBalance(ctx, address, commitment)
	})
	if err != nil {
		return nil, err
	}
	return result.(*rpc.GetTokenAccountBalanceResult), nil
}

func (r *RPCClient) NewGetRecentBlockhash(ctx context.Context, commitment rpc.CommitmentType) (*rpc.GetRecentBlockhashResult, error) {
	result, err := r.rpcCall(ctx, func() (interface{}, error) {
		return r.Client.GetRecentBlockhash(ctx, commitment)
	})
	if err != nil {
		return nil, err
	}
	return result.(*rpc.GetRecentBlockhashResult), nil
}

func (r *RPCClient) NewGetMinimumBalanceForRentExemption(ctx context.Context, size uint64, commitment rpc.CommitmentType) (uint64, error) {
	result, err := r.rpcCall(ctx, func() (interface{}, error) {
		return r.Client.GetMinimumBalanceForRentExemption(ctx, size, commitment)
	})
	if err != nil {
		return 0, err
	}
	return result.(uint64), nil
}

func (r *RPCClient) NewGetAccountInfo(ctx context.Context, account solana.PublicKey) (*rpc.GetAccountInfoResult, error) {
	result, err := r.rpcCall(ctx, func() (interface{}, error) {
		return r.Client.GetAccountInfo(ctx, account)
	})
	if err != nil {
		return nil, err
	}
	return result.(*rpc.GetAccountInfoResult), nil
}

func (r *RPCClient) NewGetProgramAccounts(ctx context.Context, program solana.PublicKey) (rpc.GetProgramAccountsResult, error) {
	result, err := r.rpcCall(ctx, func() (interface{}, error) {
		return r.Client.GetProgramAccounts(ctx, program)
	})
	if err != nil {
		return nil, err
	}
	return result.(rpc.GetProgramAccountsResult), nil
}

func (r *RPCClient) NewGetSignatureStatuses(ctx context.Context, searchTransactionHistory bool, transactionSignatures ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	result, err := r.rpcCall(ctx, func() (interface{}, error) {
		return r.Client.GetSignatureStatuses(ctx, searchTransactionHistory, transactionSignatures...)
	})
	if err != nil {
		return nil, err
	}
	return result.(*rpc.GetSignatureStatusesResult), nil
}

func (r *RPCClient) NewGetTransaction(ctx context.Context, signature solana.Signature, opts *rpc.GetTransactionOpts) (*rpc.GetTransactionResult, error) {
	result, err := r.rpcCall(ctx, func() (interface{}, error) {
		return r.Client.GetTransaction(ctx, signature, opts)
	})
	if err != nil {
		return nil, err
	}
	return result.(*rpc.GetTransactionResult), nil
}

func (r *RPCClient) NewSendTransactionWithOpts(ctx context.Context, tx *solana.Transaction, opts rpc.TransactionOpts) (solana.Signature, error) {
	result, err := r.rpcCall(ctx, func() (interface{}, error) {
		return r.Client.SendTransactionWithOpts(ctx, tx, opts)
	})
	if err != nil {
		return solana.Signature{}, err
	}
	return result.(solana.Signature), nil
}

// 从字符串解析账户私钥
func parseAccountFromString(recipient string, index int, operation string) (solana.PrivateKey, error) {
	parts := strings.Split(recipient, "----")
	if len(parts) <= 1 {
		return solana.PrivateKey{}, fmt.Errorf("invalid recipient format")
	}

	fromAccount, err := solana.PrivateKeyFromBase58(parts[1])
	if err != nil {
		logger.Error(operation, "序号", index+1, "状态", "解析私钥失败!", "错误", err)
		return solana.PrivateKey{}, err
	}

	return fromAccount, nil
}

// SendTransaction 发送交易并处理重试逻辑
func (c *Config) SendTransaction(ctx context.Context, transaction *solana.Transaction) (solana.Signature, error) {
	opts := rpc.TransactionOpts{
		SkipPreflight:       false,
		PreflightCommitment: rpc.CommitmentFinalized,
	}

	for i := 0; i < defaultRetryCount; i++ {
		sig, err := c.rpcClient.NewSendTransactionWithOpts(ctx, transaction, opts)
		if err == nil {
			return sig, nil
		}

		if !strings.Contains(err.Error(), "exceeded limit for sendTransaction") {
			return solana.Signature{}, fmt.Errorf("发送交易失败: %w", err)
		}

		select {
		case <-ctx.Done():
			return solana.Signature{}, ctx.Err()
		case <-time.After(defaultRetryDelay):
			continue
		}
	}

	return solana.Signature{}, fmt.Errorf("发送交易超过最大重试次数 (%d)", defaultRetryCount)
}

// WaitForConfirmation 等待交易确认并处理各种状态
func (c *Config) WaitForConfirmation(ctx context.Context, sig solana.Signature) (bool, error) {
	sub, err := c.wsClient.SignatureSubscribe(sig, rpc.CommitmentFinalized)
	if err != nil {
		return false, fmt.Errorf("订阅交易状态失败: %w", err)
	}
	defer sub.Unsubscribe()

	timeoutCtx, cancel := context.WithTimeout(ctx, defaultConfirmTimeout)
	defer cancel()

	for {
		select {
		case <-timeoutCtx.Done():
			if timeoutCtx.Err() == context.DeadlineExceeded {
				return false, fmt.Errorf("交易确认超时 (等待时间: %v)", defaultConfirmTimeout)
			}
			return false, ctx.Err()

		case resp, ok := <-sub.Response():
			if !ok {
				return false, fmt.Errorf("订阅连接已关闭")
			}

			if resp.Value.Err != nil {
				return true, fmt.Errorf("交易已确认但执行失败: %v", resp.Value.Err)
			}

			return true, nil

		case err := <-sub.Err():
			return false, fmt.Errorf("订阅出错: %w", err)
		}
	}
}

// 批量分发SOL
func (c *Config) batchSend() error {
	ctx := context.Background()

	feePayer, err := solana.PrivateKeyFromBase58(c.PrivateKey)
	if err != nil {
		logger.Error("批量分发", "状态", "解析私钥失败!", "错误", err)
		return err
	}

	// 使用WaitGroup和信号量控制并发
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentTx)
	defer close(sem)

	batchSize := c.Batch
	totalBatches := int(math.Ceil(float64(len(c.Recipients)) / float64(batchSize)))

	for i := 0; i < totalBatches; i++ {
		start := i * batchSize
		end := start + batchSize
		if end > len(c.Recipients) {
			end = len(c.Recipients)
		}

		instructions := make([]solana.Instruction, 0, end-start)
		for _, recipient := range c.Recipients[start:end] {
			parts := strings.Split(recipient, "----")
			if len(parts) < 2 {
				logger.Error("批量分发", "批次", i+1, "状态", "无效的接收地址格式!", "地址", recipient)
				continue
			}

			recipientPubkey, err := solana.PublicKeyFromBase58(parts[0])
			if err != nil {
				logger.Error("批量分发", "批次", i+1, "状态", "解析接收地址失败!", "错误", err)
				continue
			}

			instruction := system.NewTransferInstruction(
				uint64(c.Amount*lamportsPerSol),
				feePayer.PublicKey(),
				recipientPubkey,
			).Build()

			instructions = append(instructions, instruction)
		}

		if len(instructions) == 0 {
			logger.Error("批量分发", "批次", i+1, "状态", "没有有效的交易指令!")
			continue
		}

		recent, err := c.rpcClient.NewGetLatestBlockhash(ctx, rpc.CommitmentFinalized)
		if err != nil {
			logger.Error("批量分发", "批次", i+1, "状态", "获取最新区块哈希失败!", "错误", err)
			continue
		}

		tx, err := solana.NewTransaction(
			instructions,
			recent.Value.Blockhash,
			solana.TransactionPayer(feePayer.PublicKey()),
		)
		if err != nil {
			logger.Error("批量分发", "批次", i+1, "状态", "创建交易失败!", "错误", err)
			continue
		}

		_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
			if feePayer.PublicKey().Equals(key) {
				return &feePayer
			}
			return nil
		})
		if err != nil {
			logger.Error("批量分发", "批次", i+1, "状态", "签名交易失败!", "错误", err)
			continue
		}

		// 控制并发发送交易
		sem <- struct{}{} // 获取信号量
		wg.Add(1)

		go c.sendAndConfirmTransaction(ctx, tx, i+1, "批量分发", nil, sem, &wg)
	}

	wg.Wait() // 等待所有交易完成
	logger.Info("批量分发", "状态", "所有批次处理完成!")

	return nil
}

// 归集SOL到主账户,大号支付手续费
func (c *Config) batchCollect() error {
	ctx := context.Background()

	// 解码主账户私钥
	feePayer, err := solana.PrivateKeyFromBase58(c.PrivateKey)
	if err != nil {
		logger.Error("归集SOL", "状态", "解析主账户私钥失败!", "错误", err)
		return err
	}

	// 使用WaitGroup和信号量控制并发
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentTx)
	defer close(sem)

	type accountInfo struct {
		privateKey solana.PrivateKey
		balance    uint64
	}

	// 创建一个批次处理函数
	processBatch := func(batchNum int, accounts []accountInfo) {
		var instructions []solana.Instruction

		// 构建转账指令
		for _, account := range accounts {
			instruction := system.NewTransferInstruction(
				account.balance,
				account.privateKey.PublicKey(),
				feePayer.PublicKey(),
			).Build()

			instructions = append(instructions, instruction)
		}

		recent, err := c.rpcClient.NewGetLatestBlockhash(ctx, rpc.CommitmentFinalized)
		if err != nil {
			logger.Error("归集SOL", "批次", batchNum, "状态", "获取最新区块哈希失败!", "错误", err)
			return
		}

		tx, err := solana.NewTransaction(
			instructions,
			recent.Value.Blockhash,
			solana.TransactionPayer(feePayer.PublicKey()),
		)
		if err != nil {
			logger.Error("归集SOL", "批次", batchNum, "状态", "创建交易失败!", "错误", err)
			return
		}

		// 签名交易
		_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
			if feePayer.PublicKey().Equals(key) {
				return &feePayer
			}
			for _, account := range accounts {
				if account.privateKey.PublicKey().Equals(key) {
					pk := account.privateKey
					return &pk
				}
			}
			return nil
		})
		if err != nil {
			logger.Error("归集SOL", "批次", batchNum, "状态", "签名交易失败!", "错误", err)
			return
		}

		// 控制并发发送交易
		sem <- struct{}{} // 获取信号量
		wg.Add(1)

		go c.sendAndConfirmTransaction(ctx, tx, batchNum, "归集SOL", nil, sem, &wg)
	}

	currentBatch := make([]accountInfo, 0, c.CollectBatch)
	batchNum := 1
	totalAccounts := 0

	// 处理每个账户
	for i, recipient := range c.Recipients {
		fromAccount, err := parseAccountFromString(recipient, i, "归集SOL")
		if err != nil {
			continue
		}

		balance, err := c.rpcClient.NewGetBalance(
			ctx,
			fromAccount.PublicKey(),
			rpc.CommitmentFinalized,
		)
		if err != nil {
			logger.Error("归集SOL", "序号", i+1, "状态", "获取余额失败!", "错误", err)
			continue
		}

		if balance.Value <= 0 {
			logger.Error("归集SOL", "序号", i+1, "状态", "账户余额不足!", "地址", fromAccount.PublicKey())
			continue
		}

		currentBatch = append(currentBatch, accountInfo{
			privateKey: fromAccount,
			balance:    balance.Value,
		})
		totalAccounts++

		// 当收集到足够的账户时，立即处理这个批次
		if len(currentBatch) >= c.CollectBatch {
			processBatch(batchNum, currentBatch)
			currentBatch = make([]accountInfo, 0, c.CollectBatch)
			batchNum++
		}
	}

	// 处理最后一个不完整的批次
	if len(currentBatch) > 0 {
		processBatch(batchNum, currentBatch)
	}

	wg.Wait() // 等待所有交易完成
	logger.Info("归集SOL", "状态", "所有批次处理完成!", "总账户数", totalAccounts)

	return nil
}

// 批量归集代币
func (c *Config) tokenTransferBatch(tokenaddress string, closeAta bool) error {
	ctx := context.Background()

	feePayer, err := solana.PrivateKeyFromBase58(c.PrivateKey)
	if err != nil {
		logger.Error("归集代币", "状态", "解析主账户私钥失败!", "错误", err)
		return err
	}

	tokenMint, err := solana.PublicKeyFromBase58(tokenaddress)
	if err != nil {
		logger.Error("归集代币", "状态", "解析代币地址失败!", "错误", err)
		return err
	}

	// 使用WaitGroup和信号量控制并发
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentTx)
	defer close(sem)

	type accountInfo struct {
		privateKey solana.PrivateKey
		ataAccount solana.PublicKey
		balance    uint64
		decimals   uint8
	}

	// 获取大号代币账户
	feePayerAta, _, err := solana.FindAssociatedTokenAddress(feePayer.PublicKey(), tokenMint)
	if err != nil {
		logger.Error("归集代币", "状态", "获取大号代币账户失败!", "错误", err)
		return err
	}

	var processingError error
	var errorMutex sync.Mutex

	// 创建批次处理函数
	processBatch := func(batchNum int, accounts []accountInfo) {
		var instructions []solana.Instruction

		// 构建转账指令
		for _, account := range accounts {
			// 转账指令
			transferIx := token.NewTransferInstruction(
				account.balance,
				account.ataAccount,
				feePayerAta,
				account.privateKey.PublicKey(),
				[]solana.PublicKey{},
			).Build()

			instructions = append(instructions, transferIx)

			if closeAta {
				// 关闭代币账户指令
				closeIx := token.NewCloseAccountInstruction(
					account.ataAccount,
					feePayer.PublicKey(),
					account.privateKey.PublicKey(),
					[]solana.PublicKey{},
				).Build()
				instructions = append(instructions, closeIx)
			}
		}

		recent, err := c.rpcClient.NewGetLatestBlockhash(ctx, rpc.CommitmentFinalized)
		if err != nil {
			logger.Error("归集代币", "批次", batchNum, "状态", "获取最新区块哈希失败!", "错误", err)
			errorMutex.Lock()
			processingError = err
			errorMutex.Unlock()
			return
		}

		tx, err := solana.NewTransaction(
			instructions,
			recent.Value.Blockhash,
			solana.TransactionPayer(feePayer.PublicKey()),
		)
		if err != nil {
			logger.Error("归集代币", "批次", batchNum, "状态", "创建交易失败!", "错误", err)
			errorMutex.Lock()
			processingError = err
			errorMutex.Unlock()
			return
		}

		// 签名交易
		_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
			if feePayer.PublicKey().Equals(key) {
				return &feePayer
			}
			for _, account := range accounts {
				if account.privateKey.PublicKey().Equals(key) {
					pk := account.privateKey
					return &pk
				}
			}
			return nil
		})
		if err != nil {
			logger.Error("归集代币", "批次", batchNum, "状态", "签名交易失败!", "错误", err)
			errorMutex.Lock()
			processingError = err
			errorMutex.Unlock()
			return
		}

		// 控制并发发送交易
		sem <- struct{}{} // 获取信号量
		wg.Add(1)

		addresses := make([]string, len(accounts))
		for i, acc := range accounts {
			addresses[i] = acc.privateKey.PublicKey().String()
		}
		go c.sendAndConfirmTransaction(ctx, tx, batchNum, "归集代币", addresses, sem, &wg)
	}

	currentBatch := make([]accountInfo, 0, 5) // 代币归集使用固定的批次大小5
	batchNum := 1
	totalAccounts := 0
	var hasErrors bool

	// 处理每个账户
	for i, recipient := range c.Recipients {
		fromAccount, err := parseAccountFromString(recipient, i, "归集代币")
		if err != nil {
			hasErrors = true
			continue
		}

		// 获取小号代币账户
		fromAccountAta, _, err := solana.FindAssociatedTokenAddress(fromAccount.PublicKey(), tokenMint)
		if err != nil {
			logger.Error("归集代币", "序号", i+1, "状态", "获取小号代币账户失败!", "错误", err)
			hasErrors = true
			continue
		}

		// 获取代币余额
		balance, err := c.rpcClient.NewGetTokenAccountBalance(ctx, fromAccountAta, rpc.CommitmentFinalized)
		if err != nil {
			logger.Error("归集代币", "序号", i+1, "状态", "获取代币余额失败!", "错误", err)
			hasErrors = true
			continue
		}

		if balance.Value.Amount == "0" {
			continue
		}

		// 计算实际转账金额
		amount := uint64(*balance.Value.UiAmount * math.Pow10(int(balance.Value.Decimals)))

		currentBatch = append(currentBatch, accountInfo{
			privateKey: fromAccount,
			ataAccount: fromAccountAta,
			balance:    amount,
			decimals:   balance.Value.Decimals,
		})
		totalAccounts++

		// 当收集到足够的账户时，立即处理这个批次
		if len(currentBatch) >= 5 { // 代币归集使用固定的批次大小5
			processBatch(batchNum, currentBatch)
			currentBatch = make([]accountInfo, 0, 5)
			batchNum++
		}
	}

	// 处理最后一个不完整的批次
	if len(currentBatch) > 0 {
		processBatch(batchNum, currentBatch)
	}

	wg.Wait() // 等待所有交易完成
	logger.Info("归集代币", "状态", "所有批次处理完成!", "总账户数", totalAccounts)

	if processingError != nil {
		return processingError
	}
	if hasErrors {
		return fmt.Errorf("部分账户处理失败")
	}
	return nil
}

// 发送并等待交易确认
func (c *Config) sendAndConfirmTransaction(ctx context.Context, tx *solana.Transaction, batchNum int, operation string, addresses []string, sem chan struct{}, wg *sync.WaitGroup) {
	defer func() {
		<-sem // 释放信号量
		wg.Done()
	}()

	sig, err := c.SendTransaction(ctx, tx)
	if err != nil {
		logger.Error(operation, "批次", batchNum, "状态", "发送交易失败!", "错误", err)
		return
	}

	if len(addresses) > 0 {
		logger.Info(operation, "批次", batchNum, "状态", "转账发送成功!", "交易ID", sig, "账户数量", len(addresses), "账户地址", strings.Join(addresses, ","))
	} else {
		logger.Info(operation, "批次", batchNum, "状态", "转账发送成功!", "交易ID", sig)
	}

	// 等待交易确认
	confirmed, err := c.WaitForConfirmation(ctx, sig)
	if err != nil {
		logger.Error(operation, "批次", batchNum, "状态", "转账确认失败!", "错误", err)
		return
	}

	if confirmed {
		logger.Warn(operation, "批次", batchNum, "状态", "转账确认成功!", "交易ID", sig)
	}
}

// 关闭指定代币的所有空余额ATA账户
func (c *Config) closeSpecificTokenAtas(tokenaddress string) error {
	ctx := context.Background()

	feePayer, err := solana.PrivateKeyFromBase58(c.PrivateKey)
	if err != nil {
		logger.Error("关闭ATA", "状态", "解析主账户私钥失败!", "错误", err)
		return err
	}

	tokenMint, err := solana.PublicKeyFromBase58(tokenaddress)
	if err != nil {
		logger.Error("关闭ATA", "状态", "解析代币地址失败!", "错误", err)
		return err
	}

	// 使用WaitGroup和信号量控制并发
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentTx)
	defer close(sem)

	type accountInfo struct {
		privateKey solana.PrivateKey
		ataAccount solana.PublicKey
	}

	var processingError error
	var errorMutex sync.Mutex

	// 创建批次处理函数
	processBatch := func(batchNum int, accounts []accountInfo) {
		var instructions []solana.Instruction
		if err != nil {
			errorMutex.Lock()
			if processingError == nil {
				processingError = fmt.Errorf("error parsing fee payer key in batch %d: %v", batchNum, err)
			}
			errorMutex.Unlock()
			return
		}

		// 构建关闭账户指令
		for _, account := range accounts {
			closeIx := token.NewCloseAccountInstruction(
				account.ataAccount,
				feePayer.PublicKey(),
				account.privateKey.PublicKey(),
				[]solana.PublicKey{account.privateKey.PublicKey()},
			).Build()
			instructions = append(instructions, closeIx)
		}

		// 如果没有指令，直接返回
		if len(instructions) == 0 {
			return
		}

		// 获取最新区块哈希
		recent, err := c.rpcClient.NewGetLatestBlockhash(context.Background(), rpc.CommitmentFinalized)
		if err != nil {
			errorMutex.Lock()
			if processingError == nil {
				processingError = fmt.Errorf("error getting latest blockhash in batch %d: %v", batchNum, err)
			}
			errorMutex.Unlock()
			return
		}

		// 创建交易
		tx, err := solana.NewTransaction(
			instructions,
			recent.Value.Blockhash,
			solana.TransactionPayer(feePayer.PublicKey()),
		)
		if err != nil {
			errorMutex.Lock()
			if processingError == nil {
				processingError = fmt.Errorf("error creating transaction in batch %d: %v", batchNum, err)
			}
			errorMutex.Unlock()
			return
		}

		// 签名交易
		_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
			if feePayer.PublicKey().Equals(key) {
				return &feePayer
			}
			for _, account := range accounts {
				if account.privateKey.PublicKey().Equals(key) {
					pk := account.privateKey
					return &pk
				}
			}
			return nil
		})
		if err != nil {
			errorMutex.Lock()
			if processingError == nil {
				processingError = fmt.Errorf("error signing transaction in batch %d: %v", batchNum, err)
			}
			errorMutex.Unlock()
			return
		}

		// 控制并发发送交易
		sem <- struct{}{} // 获取信号量
		wg.Add(1)

		addresses := make([]string, len(accounts))
		for i, acc := range accounts {
			addresses[i] = acc.privateKey.PublicKey().String()
		}
		go c.sendAndConfirmTransaction(context.Background(), tx, batchNum, "关闭ATA", addresses, sem, &wg)
	}

	currentBatch := make([]accountInfo, 0, 5)
	batchNum := 1
	totalAccounts := 0
	var hasErrors bool

	// 处理每个账户
	for i, recipient := range c.Recipients {
		fromAccount, err := parseAccountFromString(recipient, i, "关闭ATA")
		if err != nil {
			hasErrors = true
			continue
		}

		// 获取小号代币账户
		fromAccountAta, _, err := solana.FindAssociatedTokenAddress(fromAccount.PublicKey(), tokenMint)
		if err != nil {
			logger.Error("关闭ATA", "序号", i+1, "状态", "获取小号代币账户失败!", "错误", err)
			hasErrors = true
			continue
		}

		// 获取代币余额
		balance, err := c.rpcClient.NewGetTokenAccountBalance(ctx, fromAccountAta, rpc.CommitmentFinalized)
		if err != nil {
			logger.Error("关闭ATA", "序号", i+1, "状态", "获取代币余额失败!", "错误", err)
			hasErrors = true
			continue
		}

		// 只处理余额为0的账户
		if balance.Value.Amount != "0" {
			continue
		}

		currentBatch = append(currentBatch, accountInfo{
			privateKey: fromAccount,
			ataAccount: fromAccountAta,
		})
		totalAccounts++

		// 当收集到足够的账户时，立即处理这个批次
		if len(currentBatch) >= 5 {
			processBatch(batchNum, currentBatch)
			currentBatch = make([]accountInfo, 0, 5)
			batchNum++
		}
	}

	// 处理最后一个不完整的批次
	if len(currentBatch) > 0 {
		processBatch(batchNum, currentBatch)
	}

	if hasErrors {
		return fmt.Errorf("部分账户处理失败")
	}

	logger.Info("关闭ATA", "状态", "所有批次处理完成!", "总账户数", totalAccounts)
	return processingError
}

// 关闭所有空余额ATA账户
func (c *Config) closeAllAtas() error {
	ctx := context.Background()

	feePayer, err := solana.PrivateKeyFromBase58(c.PrivateKey)
	if err != nil {
		logger.Error("关闭所有ATA", "状态", "解析主账户私钥失败!", "错误", err)
		return err
	}

	// 使用WaitGroup和信号量控制并发
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentTx)
	defer close(sem)

	type accountInfo struct {
		privateKey solana.PrivateKey
		ataAccount solana.PublicKey
	}

	var processingError error
	var errorMutex sync.Mutex

	// 创建批次处理函数
	processBatch := func(batchNum int, accounts []accountInfo) {
		var instructions []solana.Instruction

		// 构建关闭账户指令
		for _, account := range accounts {
			closeIx := token.NewCloseAccountInstruction(
				account.ataAccount,
				feePayer.PublicKey(),
				account.privateKey.PublicKey(),
				[]solana.PublicKey{},
			).Build()
			instructions = append(instructions, closeIx)
		}

		recent, err := c.rpcClient.NewGetLatestBlockhash(ctx, rpc.CommitmentFinalized)
		if err != nil {
			logger.Error("关闭所有ATA", "批次", batchNum, "状态", "获取最新区块哈希失败!", "错误", err)
			errorMutex.Lock()
			processingError = err
			errorMutex.Unlock()
			return
		}

		tx, err := solana.NewTransaction(
			instructions,
			recent.Value.Blockhash,
			solana.TransactionPayer(feePayer.PublicKey()),
		)
		if err != nil {
			logger.Error("关闭所有ATA", "批次", batchNum, "状态", "创建交易失败!", "错误", err)
			errorMutex.Lock()
			processingError = err
			errorMutex.Unlock()
			return
		}

		// 签名交易
		_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
			if feePayer.PublicKey().Equals(key) {
				return &feePayer
			}
			for _, account := range accounts {
				if account.privateKey.PublicKey().Equals(key) {
					pk := account.privateKey
					return &pk
				}
			}
			return nil
		})
		if err != nil {
			logger.Error("关闭所有ATA", "批次", batchNum, "状态", "签名交易失败!", "错误", err)
			errorMutex.Lock()
			processingError = err
			errorMutex.Unlock()
			return
		}

		// 控制并发发送交易
		sem <- struct{}{} // 获取信号量
		wg.Add(1)

		addresses := make([]string, len(accounts))
		for i, acc := range accounts {
			addresses[i] = acc.privateKey.PublicKey().String()
		}
		go c.sendAndConfirmTransaction(ctx, tx, batchNum, "关闭所有ATA", addresses, sem, &wg)
	}

	currentBatch := make([]accountInfo, 0, 5)
	batchNum := 1
	totalAccounts := 0
	var hasErrors bool

	// 处理每个账户
	for i, recipient := range c.Recipients {
		fromAccount, err := parseAccountFromString(recipient, i, "关闭所有ATA")
		if err != nil {
			hasErrors = true
			continue
		}

		// 获取账户所有代币账户
		accounts, err := c.rpcClient.NewGetTokenAccountsByOwner(
			ctx,
			fromAccount.PublicKey(),
			&rpc.GetTokenAccountsConfig{
				ProgramId: &solana.TokenProgramID,
			},
			&rpc.GetTokenAccountsOpts{
				Commitment: rpc.CommitmentFinalized,
			},
		)
		if err != nil {
			logger.Error("关闭所有ATA", "序号", i+1, "状态", "获取代币账户失败!", "错误", err)
			hasErrors = true
			continue
		}

		// 处理每个代币账户
		for _, account := range accounts.Value {
			balance, err := c.rpcClient.NewGetTokenAccountBalance(
				ctx,
				account.Pubkey,
				rpc.CommitmentFinalized,
			)
			if err != nil {
				logger.Error("关闭所有ATA", "序号", i+1, "状态", "获取代币余额失败!", "错误", err)
				hasErrors = true
				continue
			}

			// 只处理余额为0的账户
			if balance.Value.Amount != "0" {
				continue
			}

			currentBatch = append(currentBatch, accountInfo{
				privateKey: fromAccount,
				ataAccount: account.Pubkey,
			})
			totalAccounts++

			// 当收集到足够的账户时，立即处理这个批次
			if len(currentBatch) >= 5 {
				processBatch(batchNum, currentBatch)
				currentBatch = make([]accountInfo, 0, 5)
				batchNum++
			}
		}
	}

	// 处理最后一个不完整的批次
	if len(currentBatch) > 0 {
		processBatch(batchNum, currentBatch)
	}

	if hasErrors {
		return fmt.Errorf("部分账户处理失败")
	}

	logger.Info("关闭所有ATA", "状态", "所有批次处理完成!", "总账户数", totalAccounts)
	return processingError
}

// 查询SOL余额
func (c *Config) getBalance(pubkey string) (float64, error) {
	// 解析公钥
	publicKey, err := solana.PublicKeyFromBase58(pubkey)
	if err != nil {
		return 0, fmt.Errorf("解析公钥失败: %v", err)
	}

	// 查询余额
	balance, err := c.rpcClient.NewGetBalance(
		context.TODO(),
		publicKey,
		rpc.CommitmentFinalized,
	)
	if err != nil {
		return 0, fmt.Errorf("查询余额失败: %v", err)
	}

	// 将 lamports 转换为 SOL
	solBalance := float64(balance.Value) / 1e9
	return solBalance, nil
}

// 批量查询SOL余额
func (c *Config) getBalanceBatch() error {
	// 创建文件用于保存结果
	file, err := os.Create("balance_results.txt")
	if err != nil {
		logger.Error("查询SOL余额", "状态", "创建文件失败!", "错误", err)
		return err
	}
	defer file.Close()

	// 使用互斥锁保护文件写入和错误标记
	var mu sync.Mutex
	var hasErrors bool

	// 创建等待组和信号量
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // 限制10个并发

	for _, recipient := range c.Recipients {
		wg.Add(1)
		sem <- struct{}{} // 获取信号量

		go func(recipient string) {
			defer wg.Done()
			defer func() { <-sem }() // 释放信号量

			pubkey := strings.Split(recipient, "----")[0]
			privateKey := strings.Split(recipient, "----")[1]
			balance, err := c.getBalance(pubkey)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				logger.Error("查询SOL余额", "状态", "地址查询余额失败!", "错误", err)
				hasErrors = true
				return
			}

			logger.Warn("查询SOL余额", "地址", pubkey, "余额", balance)
			file.WriteString(fmt.Sprintf("%s----%s----%f\r\n", pubkey, privateKey, balance))
		}(recipient)
	}

	wg.Wait() // 等待所有goroutine完成

	if hasErrors {
		return fmt.Errorf("部分地址余额查询失败")
	}
	return nil
}

// 查询指定代币余额
func (c *Config) getTokenBalance(pubkey string, tokenMint solana.PublicKey) (float64, error) {
	// 解析公钥
	publicKey, err := solana.PublicKeyFromBase58(pubkey)
	if err != nil {
		return 0, fmt.Errorf("解析公钥失败: %v", err)
	}

	// 获取代币账户
	atas, err := c.rpcClient.GetTokenAccountsByOwner(
		context.TODO(),
		publicKey,
		&rpc.GetTokenAccountsConfig{
			Mint: &tokenMint,
		},
		&rpc.GetTokenAccountsOpts{})

	if err != nil || len(atas.Value) == 0 {
		return 0, fmt.Errorf("获取代币账户失败: %v", err)
	}

	// 获取代币余额
	balance, err := c.rpcClient.GetTokenAccountBalance(
		context.TODO(),
		atas.Value[0].Pubkey,
		rpc.CommitmentFinalized,
	)
	if err != nil {
		return 0, fmt.Errorf("查询代币余额失败: %v", err)
	}
	// 将余额转换为浮点数
	amount, err := strconv.ParseFloat(balance.Value.Amount, 64)
	if err != nil {
		return 0, fmt.Errorf("解析代币余额失败: %v", err)
	}
	tokenBalance := amount / math.Pow10(int(balance.Value.Decimals))
	return tokenBalance, nil
}

// 批量查询指定代币余额
func (c *Config) getTokenBalanceBatch(tokenaddress string) error {
	// 解析代币地址
	tokenMint, err := solana.PublicKeyFromBase58(tokenaddress)
	if err != nil {
		logger.Error("查询代币余额", "状态", "解析代币址失败!", "错误", err)
		return err
	}

	// 创建文件保存结果
	file, err := os.Create("token_balance_results.txt")
	if err != nil {
		logger.Error("查询代币余额", "状态", "创建文件失败!", "错误", err)
		return err
	}
	defer file.Close()

	// 使用互斥锁保护文件写入
	var mu sync.Mutex

	// 创建等待组和信号量
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // 限制10个并发

	for _, recipient := range c.Recipients {
		wg.Add(1)
		sem <- struct{}{} // 获取信号量

		go func(recipient string) {
			defer wg.Done()
			defer func() { <-sem }() // 释放信号量

			pubkey := strings.Split(recipient, "----")[0]
			privateKey := strings.Split(recipient, "----")[1]
			balance, err := c.getTokenBalance(pubkey, tokenMint)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				logger.Error("查询代币余额", "状态", "地址查询代币余额失败!", "错误", err)
				return
			}

			logger.Warn("查询代币余额", "地址", pubkey, "代币余额", balance)
			file.WriteString(fmt.Sprintf("%s----%s----%f\r\n", pubkey, privateKey, balance))
		}(recipient)
	}

	wg.Wait() // 等待所有goroutine完成
	return nil
}

// 批量查询代币余额
func (c *Config) getAccountTokenBatch() error {
	var mu sync.Mutex
	var hasErrors bool

	// 创建等待组和信号量
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // 限制10个并发

	for _, recipient := range c.Recipients {
		wg.Add(1)
		sem <- struct{}{} // 获取信号量

		go func(recipient string) {
			defer wg.Done()
			defer func() { <-sem }() // 释放信号量

			if err := c.getAccountToken(recipient); err != nil {
				mu.Lock()
				hasErrors = true
				mu.Unlock()
			}
		}(recipient)
	}

	wg.Wait() // 等待所有goroutine完成

	if hasErrors {
		return fmt.Errorf("部分账户代币查询失败")
	}
	return nil
}

// 获取账户所有代币账户
func (c *Config) getAccountToken(pubkey string) error {
	PublicKey, err := solana.PublicKeyFromBase58(pubkey)
	if err != nil {
		logger.Error("获取账户代币", "状态", "解析主账户地址失败!", "错误", err)
		return err
	}

	accounts, err := c.rpcClient.NewGetTokenAccountsByOwner(
		context.TODO(),
		PublicKey,
		&rpc.GetTokenAccountsConfig{
			ProgramId: &solana.TokenProgramID,
		},
		&rpc.GetTokenAccountsOpts{
			Commitment: rpc.CommitmentFinalized,
		},
	)
	if err != nil {
		logger.Error("获取代币账户", "状态", "获取代币账户失败!", "错误", err)
		return err
	}

	if len(accounts.Value) == 0 {
		logger.Info("获取代币账户", "状态", "没有代币账户!")
		return nil
	}

	var names []string
	var balances []string
	var hasErrors bool

	for _, account := range accounts.Value {
		balance, err := c.rpcClient.NewGetTokenAccountBalance(
			context.TODO(),
			account.Pubkey,
			rpc.CommitmentFinalized,
		)
		if err != nil {
			logger.Error("获取代币账户", "状态", "获取代币余额失败!", "错误", err)
			hasErrors = true
			continue
		}

		data := gjson.ParseBytes(account.Account.Data.GetRawJSON())
		name := data.Get("parsed.info.name").String()
		decimals := data.Get("parsed.info.decimals").Int()
		balanceStr := strconv.FormatFloat(*balance.Value.UiAmount, 'f', int(decimals), 64)

		names = append(names, name)
		balances = append(balances, balanceStr)
	}
	args := []interface{}{"地址", pubkey}
	for i := 0; i < len(names); i++ {
		args = append(args, fmt.Sprintf("代币%d", i+1), names[i])
		args = append(args, fmt.Sprintf("余额%d", i+1), balances[i])
	}
	if len(names) == 0 {
		args = append(args, "状态", "没有代币!")
	}

	logger.Info("获取账户代币", args...)

	if hasErrors {
		return fmt.Errorf("部分代币余额获取失败")
	}
	return nil
}

// 读取小号文件
func readRecipients(filePath string) ([]string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	// 按行分割并去除空行
	lines := strings.Split(string(content), "\n")
	recipients := make([]string, 0)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			recipients = append(recipients, line)
		}
	}
	return recipients, nil
}

// 读取并解析env文件
func readEnvFile() (*Config, error) {
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		envInit()
		return nil, &ConfigError{"env", "请先配置.env文件"}
	}

	envContent, err := os.ReadFile(".env")
	if err != nil {
		return nil, fmt.Errorf("读取.env文件失败: %v", err)
	}

	// 解析.env文件内容
	envMap := make(map[string]string)
	lines := strings.Split(string(envContent), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			envMap[key] = value
		}
	}

	// 验证配置
	if err := validateConfig(envMap); err != nil {
		return nil, err
	}

	// 连接WebSocket
	wsClient, err := ws.Connect(context.Background(), envMap["ws"])
	if err != nil {
		logger.Error("连接WebSocket", "状态", "连接失败!", "错误", err)
		return nil, fmt.Errorf("连接WebSocket失败: %v", err)
	}

	// 解析数值配置
	amount, _ := strconv.ParseFloat(envMap["amount"], 64)
	batch, _ := strconv.Atoi(envMap["batch"])
	collectBatch, _ := strconv.Atoi(envMap["collectBatch"])

	return &Config{
		rpcClient:    &RPCClient{rpc.New(envMap["rpc"])},
		wsClient:     wsClient,
		PrivateKey:   envMap["privateKey"],
		Amount:       amount,
		Batch:        batch,
		CollectBatch: collectBatch,
	}, nil
}

// 生成新钱包
func generateWallet() error {
	// 创建文件保存结果
	file, err := os.Create("wallets.txt")
	if err != nil {
		return fmt.Errorf("保存到文件失败: %v", err)
	}
	defer file.Close()

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // 限制10个并发

	for i := 0; i < 150000; i++ {
		wg.Add(1)
		sem <- struct{}{} // 获取信号量

		go func(index int) {
			defer wg.Done()
			defer func() { <-sem }() // 释放信号量

			wallet := solana.NewWallet()
			privateKey := wallet.PrivateKey.String()
			publicKey := wallet.PublicKey().String()

			mu.Lock()
			_, err := file.WriteString(fmt.Sprintf("%s----%s\n", publicKey, privateKey))
			if err != nil {
				logger.Error("生成钱包", "状态", "写入文件失败!", "错误", err)
			}
			mu.Unlock()

			logger.Warn("生成钱包", "序号", index+1, "地址", publicKey)
		}(i)
	}

	wg.Wait() // 等待所有goroutine完成
	return nil
}

func envInit() {
	envDefaultText := `# 大号私钥
privateKey=
# 批量转账每包地址数量
batch=20
# 归集转账每包地址数量
collectBatch=5
# http RPC
rpc=https://mainnet.helius-rpc.com/?api-key=d773ff1a-93f5-4ac8-94e3-29b252dd4fb1
# WS RPC
ws=wss://mainnet.helius-rpc.com/?api-key=d773ff1a-93f5-4ac8-94e3-29b252dd4fb1
# 转账金额 单位 SOL
amount=0.001`
	os.WriteFile(".env", []byte(envDefaultText), 0644)
}

// 菜单选项
type MenuOption struct {
	id          int
	description string
	handler     func(*Config, string) error
}

// 主菜单选项
var menuOptions = []MenuOption{
	{1, "批量分发 SOL", func(c *Config, _ string) error { return c.batchSend() }},
	{2, "批量归集 SOL (大号出手续费)", func(c *Config, _ string) error { return c.batchCollect() }},
	{3, "批量归集 SOL (小号出手续费)", func(c *Config, _ string) error { return fmt.Errorf("功能未实现") }},
	{4, "查询 SOL 余额", func(c *Config, _ string) error { return c.getBalanceBatch() }},
	{5, "查询指定代币余额", func(c *Config, mint string) error { return c.getTokenBalanceBatch(mint) }},
	{6, "查询所有代币余额", func(c *Config, _ string) error { return c.getAccountTokenBatch() }},
	{7, "归集代币（关闭代币账户）", func(c *Config, mint string) error { return c.tokenTransferBatch(mint, true) }},
	{8, "归集代币（不关闭代币账户）", func(c *Config, mint string) error { return c.tokenTransferBatch(mint, false) }},
	{9, "批量关闭指定代币的空余额ATA账户", func(c *Config, mint string) error { return c.closeSpecificTokenAtas(mint) }},
	{10, "批量关闭所有空余额ATA账户", func(c *Config, _ string) error { return c.closeAllAtas() }},
	{11, "生成新钱包", func(c *Config, _ string) error { return generateWallet() }},
}

func (c *Config) loadaccounts() error {
	var filePath string
	fmt.Print("\n请输入小号文件路径(小号文件格式: 地址----私钥): ")
	fmt.Scanln(&filePath)

	recipients, err := readRecipients(filePath)
	if err != nil {
		logger.Error("读取小号文件失败", "错误", err)
		fmt.Printf("\n❌ 错误: %v\n按回车键继续...", err)
		fmt.Scanln()
		return err
	}
	c.Recipients = recipients
	logger.Info("成功读取小号", "数量", len(recipients))
	return nil
}

func main() {
	logger = initLogger()

	// 初始化配置
	c, err := readEnvFile()
	if err != nil {
		logger.Error("初始化配置失败", "错误", err)
		fmt.Printf("\n❌ 错误: %v\n按回车键继续...", err)
		fmt.Scanln()
		return
	}

	for {
		fmt.Println("\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render("=== hdd.cm 推特低至2毛  ==="))
		fmt.Println("=== Solana 工具箱 ===")

		// 显示菜单
		fmt.Println("\n=== 功能选项 ===")
		for _, opt := range menuOptions {
			fmt.Printf("%d. %s\n", opt.id, opt.description)
		}

		// 获取用户选择
		var option int
		fmt.Printf("\n请选择操作 [1-%d]: ", len(menuOptions))
		if _, err := fmt.Scanln(&option); err != nil {
			logger.Error("输入无效", "错误", err)
			continue
		}

		// 验证选项
		if option < 1 || option > len(menuOptions) {
			logger.Error("选项无效", "输入", option)
			fmt.Println("\n❌ 无效的选项")
			continue
		}
		if option != 11 {
			if err := c.loadaccounts(); err != nil {
				continue
			}
		}

		var tokenMint string
		if option == 5 || option == 7 || option == 8 || option == 9 {
			fmt.Print("\n请输入代币合约地址: ")
			fmt.Scanln(&tokenMint)
		}

		// 执行选中的操作
		selectedOption := menuOptions[option-1]

		// 执行操作并处理错误
		if err := selectedOption.handler(c, tokenMint); err != nil {
			logger.Error("操作执行失败",
				"操作", selectedOption.description,
				"错误", err)
			fmt.Printf("\n❌ 错误: %v", err)
		} else {
			logger.Info("操作执行成功",
				"操作", selectedOption.description)
		}

		fmt.Print("\n✅ 操作完成, 按回车键继续...")
		fmt.Scanln()
	}
}
