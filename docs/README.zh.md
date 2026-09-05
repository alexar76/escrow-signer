# escrow-policy-signer — HORKOS

<p align="center">
  <a href="../README.md">English</a> ·
  <a href="README.ru.md">Русский</a> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.fr.md">Français</a> ·
  <a href="README.zh.md"><b>中文</b></a>
</p>

**HORKOS**（ὅρκος）— 誓言，以及违誓者的惩罚。它是 AIMarket 生态中唯一持有在
`AIMarketEscrow.authorizedHubs` 中获授权私钥的进程。它存在的理由，正是让枢纽（Hub）**不**持有这把钥匙。

**地址：** `0xBE0bBE44cceCfEb048dd53f601C37525a3D6C5f1` · **网络：** Base 主网（8453）·
**托管合约：** `0x12Db8FAC81E5999D2f2087B79e38951571562CF2` ·
**主机：** 另一台机器，只能从 Hub 主机通过反向 SSH 隧道访问。

绝不与 Hub 同机：共用主机会把「私钥不进入 Hub 进程」变成一句话而不是一条边界 —— 取得 docker
权限的人会同时取得两者。

## 它会签什么

只有一种：对 `debitChannel(bytes32,uint256,bytes32,uint256,bytes)` 的规范调用，选择器
`0xf7becd80`，发往唯一固定的托管合约，在唯一固定的链上，且 `value == 0`。别的都不签：不签
`settleChannel`，不签代币 `transfer`，不签 `setHubAuthorization`，不签合约创建，也不换网络。

**金额**的授权来自 depositor 的 EIP-712 签名，而不是 Hub。该签名在此重新验证：对照本进程自己读取
的支付通道状态，并像合约那样把 `hub` 字段替换为**本服务自己的地址**。为别的枢纽签发的签名、用
错 nonce 的签名，或并非该通道 depositor 所签的签名，都会被拒绝。

## 为什么要带策略的签名服务，而不是把私钥放进 Hub

`AIMARKET_ESCROW_SUBMIT_STRATEGY=external` 只是把私钥移出 Hub 进程，单凭这一点收益很小：Hub
发来 `{to, data, chainId, gas, value}`，一个天真的签名服务会照签不误。被攻破的 Hub 拿着令牌就会
请求 `USDC.transfer(攻击者, 全部)`。价值完全在于拒绝，这些拒绝在 `escrow_signer/` 中列为规则
R1–R26。

没有任何签名服务能消除的残余风险，直说：**被攻破的 Hub 仍能就未交付的工作收款**，上限是速度额度，
且只限买方已经有效签署过的金额。合约检查的每个字段都包含在 depositor 的摘要中，因此这样的请求
与正当请求无法区分。缩小它的办法是更小的额度，以及买方按次签名而非预先签名。

## 部署

```
scp -r escrow-signer/ signer-host:/root/escrow-signer/
cp .env.example .env      # 在主机上，chmod 600，填入私钥与令牌
docker compose up -d --build
curl -s localhost:9500/health     # {"ok":true,"ready":true,...}
```

然后在 **Hub** 主机上：

```
cp deploy/escrow-signer-tunnel.service /etc/systemd/system/
systemctl enable --now escrow-signer-tunnel

cd /root/claudecode/aicom && ./scripts/deploy_hub_rebuild.sh --no-build \
  --set AIMARKET_ESCROW_SUBMIT_STRATEGY=external \
  --set AIMARKET_ESCROW_SIGNER_URL=http://127.0.0.1:9500/sign \
  --set AIMARKET_ESCROW_SIGNER_TOKEN="$(cat /root/.escrow-signer-token)" \
  --set AIMARKET_ESCROW_SUBMIT_CONFIRM=i-understand-this-moves-funds
```

永远先跑 `plan`：它构造真实的 calldata，并用 `eth_call` 对照实时状态运行，因此在不产生任何交易
的前提下回答「现在这笔会被接受吗？」。

```
docker exec modelmarket-hub python -m aimarket_hub.escrow_bridge.cli plan
docker exec modelmarket-hub python -m aimarket_hub.escrow_bridge.cli submit --yes
```

第四道闸是刻意保留的：任何策略下 Hub 都不会在请求路径上广播交易，所以常规结算是一个执行
`submit --yes` 的定时器，而不是后台线程。

## 运维

- `GET /health` —— 就绪状态、地址，以及若在拒绝则给出原因。不写账本。
- `GET /status` —— 当前生效的额度与账本状态。
- `GET /receipt/<receipt_id>` —— 「本服务究竟广播了什么」的权威答案。Hub 把返回的哈希当作证据，
  这里可以核对。
- 服务以**拒绝**状态启动，直到账本校验通过、链上确认它是获授权枢纽、domain separator 相符、
  并且每一条未结记录都依据链上证据归类之后，才开始接受请求。队列停住胜过一笔未计量的签名。

**这个地址同时也是收款方。** `settleChannel` 支付给 `ch.hub`，因此收入积累在这里而不是金库。
把它归集到金库是运维者另一个独立的动作。

## 额度

全部以 USDC 的整数基本单位计（6 位小数）。每一项都必须设置：缺失、为零或为负都会拒绝启动，而
「不限」必须写作 `unlimited`，并在每次启动时公告。刻意没有「每轮」额度：请求格式里没有轮次
标识，而从空闲间隔推断出的「轮次」可以靠控制节奏重置。该额度留在 Hub 一侧。

按次数的额度并不与按金额的额度重复：烧毁收据与研磨 nonce 不花任何 USDC，只受计数器约束。
`SIGNER_CAP_FEE_WEI_24H` 是第三个独立量：金额额度以代币计价，而真正被花掉的是这把私钥的 ETH。

## 测试

```
python -m pytest escrow-signer/tests -q      # 95 项测试
```

`tests/test_wire.py` 直接导入 Hub 自己的 `ExternalSigner` 类，并对真实 socket 运行它 —— 其中包括
断言**任何路由都不会返回 3xx**：`urllib` 会带着 `Authorization` 头跟随重定向，多一个尾斜杠就会
变成令牌泄露。`tests/test_policy.py` 是拒绝清单，每个用例都断言「什么都没签、什么都没广播」，
而不只是断言状态码。
