# escrow-policy-signer — HORKOS

<p align="center">
  <a href="../README.md">English</a> ·
  <a href="README.ru.md">Русский</a> ·
  <a href="README.es.md"><b>Español</b></a> ·
  <a href="README.fr.md">Français</a> ·
  <a href="README.zh.md">中文</a>
</p>

**HORKOS** (ὅρκος) — el juramento, y el castigo por romperlo. Es el único proceso del
ecosistema AIMarket que guarda una clave privada autorizada en
`AIMarketEscrow.authorizedHubs`. Existe precisamente para que el Hub **no** la guarde.

**Dirección:** `0xBE0bBE44cceCfEb048dd53f601C37525a3D6C5f1` · **Red:** Base mainnet (8453) ·
**Depósito en garantía (escrow):** `0x12Db8FAC81E5999D2f2087B79e38951571562CF2` ·
**Host:** una máquina distinta, alcanzable desde el host del Hub solo por un túnel SSH inverso.

Nunca la misma máquina que el Hub: compartir host convertiría «la clave no entra en el proceso
del Hub» en una frase en lugar de un límite — quien obtuviera acceso a docker obtendría ambos.

## Qué firma

Exactamente una cosa: una llamada canónica a
`debitChannel(bytes32,uint256,bytes32,uint256,bytes)`, selector `0xf7becd80`, al único contrato
de depósito fijado, en la única red fijada, con `value == 0`. Nada más: ni `settleChannel`, ni
un `transfer` de token, ni `setHubAuthorization`, ni la creación de un contrato, ni otra red.

La autoridad sobre el **importe** no es el Hub. Es la firma EIP-712 del depositor, verificada
de nuevo aquí contra el estado del canal de pago que este proceso leyó por su cuenta, y con
**su propia dirección** sustituyendo el campo `hub`, igual que hace el contrato. Una firma
emitida para otro hub, con otro nonce, o por alguien que no sea el depositor del canal, se
rechaza.

## Por qué un firmante con política y no una clave en el Hub

`AIMARKET_ESCROW_SUBMIT_STRATEGY=external` saca la clave del proceso del Hub y, por sí solo,
compra muy poco: el Hub envía `{to, data, chainId, gas, value}` y un firmante ingenuo firmaría
lo que le pongan. Un Hub comprometido con el token pediría `USDC.transfer(atacante, todo)`. El
valor está entero en los rechazos, enumerados como reglas R1–R26 en `escrow_signer/`.

El riesgo residual que ningún firmante cierra, dicho sin adornos: **un Hub comprometido puede
seguir cobrando por trabajo no realizado**, hasta los límites de velocidad, usando firmas que
los compradores produjeron de verdad. Todos los campos que comprueba el contrato están dentro
del digest del depositor, así que esa petición es indistinguible de una legítima. Disminuye
con límites más pequeños y con compradores que firman por invocación en vez de por adelantado.

## Despliegue

```
scp -r escrow-signer/ signer-host:/root/escrow-signer/
cp .env.example .env      # en el host, chmod 600, con la clave y el token
docker compose up -d --build
curl -s localhost:9500/health     # {"ok":true,"ready":true,...}
```

Después, en el host del **Hub**:

```
cp deploy/escrow-signer-tunnel.service /etc/systemd/system/
systemctl enable --now escrow-signer-tunnel

cd /root/claudecode/aicom && ./scripts/deploy_hub_rebuild.sh --no-build \
  --set AIMARKET_ESCROW_SUBMIT_STRATEGY=external \
  --set AIMARKET_ESCROW_SIGNER_URL=http://127.0.0.1:9500/sign \
  --set AIMARKET_ESCROW_SIGNER_TOKEN="$(cat /root/.escrow-signer-token)" \
  --set AIMARKET_ESCROW_SUBMIT_CONFIRM=i-understand-this-moves-funds
```

Primero `plan`, siempre: construye el calldata real y lo pasa por `eth_call` contra el estado
en vivo, de modo que responde «¿se aceptaría esto ahora?» sin que exista una transacción.

```
docker exec modelmarket-hub python -m aimarket_hub.escrow_bridge.cli plan
docker exec modelmarket-hub python -m aimarket_hub.escrow_bridge.cli submit --yes
```

El cuarto escalón es deliberado: en ninguna estrategia el Hub emite desde la ruta de la
petición, así que la liquidación periódica es un temporizador que ejecuta `submit --yes`, no un
hilo en segundo plano.

## Operación

- `GET /health` — disponibilidad, la dirección, y por qué rechaza si rechaza. Sin escritura.
- `GET /status` — los límites vigentes y el estado del libro.
- `GET /receipt/<receipt_id>` — la respuesta autorizada a «qué difundió realmente este
  servicio». El Hub trata el hash devuelto como prueba; aquí se puede contrastar.
- Arranca **rechazando** y sigue así hasta que el libro verifica, la cadena confirma que es un
  hub autorizado, coincide el domain separator y cada fila sin resolver queda clasificada con
  evidencia de la cadena. Una cola detenida es mejor que una firma sin medir.

**La dirección es también la beneficiaria.** `settleChannel` paga a `ch.hub`, así que los
ingresos se acumulan aquí y no en la tesorería. Barrerlos es una acción aparte del operador.

## Límites

Todos en unidades base enteras de USDC (6 decimales). Cada uno es obligatorio: un valor
ausente, cero o negativo impide arrancar, y «sin límite» se escribe `unlimited` y se anuncia
en cada arranque. No hay límite «por pasada»: el formato de la petición no lleva identificador
de pasada, y una pasada inferida de los huecos de inactividad se reinicia marcando el ritmo.
Ese límite se queda en el Hub.

Los límites por número no duplican los monetarios: quemar recibos y moler nonces no cuesta
ningún USDC y solo lo acotan los contadores. `SIGNER_CAP_FEE_WEI_24H` es una tercera magnitud
aparte: los límites monetarios se denominan en el token, mientras que lo que se gasta es el ETH
de esta clave.

## Pruebas

```
python -m pytest escrow-signer/tests -q      # 95 pruebas
```

`tests/test_wire.py` importa la propia clase `ExternalSigner` del Hub y la ejecuta contra un
socket real — incluida la comprobación de que **ninguna ruta responde nunca 3xx**: `urllib`
sigue una redirección con la cabecera `Authorization` puesta, y una barra final de más se
convertiría en una filtración del token. `tests/test_policy.py` es la tabla de rechazos, y cada
caso comprueba que no se firmó ni se difundió nada, no solo el código de estado.
