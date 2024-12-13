# [hdd.cm推特低至1毛5](https://hdd.cm/)

<img width="333" alt="image" src="https://github.com/user-attachments/assets/f7925c58-f897-451d-acb2-d00c880d5c0f" />



# Solana 基础功能工具箱

一个功能强大的基于Go语言的Solana区块链钱包管理工具，支持批量转账、归集和代币管理等操作。

## 主要功能

- 🔑 钱包生成
  - 生成新的Solana钱包地址和私钥
  
- 💸 SOL代币操作
  - 批量转账SOL到多个地址
  - 批量归集SOL到主钱包（主钱包支付手续费）
  - 批量查询SOL余额
  
- 🪙 SPL代币操作
  - 批量转账SPL代币
  - 关闭指定代币的空余额ATA账户
  - 关闭所有空余额ATA账户
  - 批量查询代币余额
  - 查询账户所有代币列表

## 环境要求

- Go 1.16 或更高版本
- Solana RPC节点访问权限
- Solana WebSocket节点访问权限

## 安装说明

1. 克隆项目代码
2. 安装依赖：
```bash
go mod init solanaTool
go mod tidy
```

## 配置说明

在项目根目录创建 `.env` 文件，配置以下参数：

```env
# 大号私钥
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
amount=0.001
```

## 使用说明

运行程序：
```bash
go run solana.go
```

程序提供以下交互式菜单选项：

1. 批量分发SOL
   - 向多个地址批量转账指定数量的SOL
   
2. 批量归集SOL
   - 将多个地址的SOL归集到主钱包
   - 手续费由主钱包支付
   
3. 代币操作
   - 批量转账指定代币
   - 关闭指定代币的空余额账户
   - 关闭所有空余额代币账户
   
4. 余额查询
   - 批量查询SOL余额
   - 批量查询指定代币余额
   - 查询账户所有代币列表
   
5. 新钱包生成

## 安全提示

- 私钥信息需要安全保管，禁止分享或泄露
- `.env` 配置文件应该添加到 `.gitignore`
- 执行转账操作前请仔细核对交易详情

## 错误处理

工具内置了完善的错误处理和重试机制，包括：
- RPC连接异常处理
- 交易失败重试
- 网络超时重试
- 配置验证

## 技术依赖

主要使用了以下Go语言包：
- `github.com/gagliardetto/solana-go`: Solana区块链交互
- `github.com/charmbracelet/log`: 日志管理
- `github.com/charmbracelet/lipgloss`: 终端样式
- `github.com/tidwall/gjson`: JSON解析

## 贡献指南

欢迎提交Pull Request来改进这个项目。

## 开源协议

本项目采用MIT协议开源。
