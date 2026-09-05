# escrow-policy-signer — HORKOS

<p align="center">
  <a href="../README.md">English</a> ·
  <a href="README.ru.md">Русский</a> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.fr.md"><b>Français</b></a> ·
  <a href="README.zh.md">中文</a>
</p>

**HORKOS** (ὅρκος) — le serment, et la punition de celui qui le rompt. C'est le seul processus
de l'écosystème AIMarket qui détient une clé privée autorisée dans
`AIMarketEscrow.authorizedHubs`. Il existe précisément pour que le Hub ne la détienne **pas**.

**Adresse :** `0xBE0bBE44cceCfEb048dd53f601C37525a3D6C5f1` · **Réseau :** Base mainnet (8453) ·
**Séquestre (escrow) :** `0x12Db8FAC81E5999D2f2087B79e38951571562CF2` ·
**Hôte :** une machine distincte, atteignable depuis l'hôte du Hub par un tunnel SSH inverse.

Jamais la même machine que le Hub : partager l'hôte transformerait « la clé n'entre pas dans le
processus du Hub » en une phrase plutôt qu'en une frontière — qui obtient l'accès à docker
obtient les deux.

## Ce qu'il signe

Exactement une chose : un appel canonique à
`debitChannel(bytes32,uint256,bytes32,uint256,bytes)`, sélecteur `0xf7becd80`, vers le seul
contrat de séquestre épinglé, sur la seule chaîne épinglée, avec `value == 0`. Rien d'autre :
ni `settleChannel`, ni un `transfer` de jeton, ni `setHubAuthorization`, ni la création d'un
contrat, ni un autre réseau.

L'autorité sur le **montant** n'est pas le Hub. C'est la signature EIP-712 du depositor,
vérifiée à nouveau ici contre l'état du canal de paiement que ce processus a lu lui-même, en
substituant **sa propre adresse** au champ `hub`, exactement comme le fait le contrat. Une
signature émise pour un autre hub, à un autre nonce, ou par quelqu'un qui n'est pas le
depositor du canal, est refusée.

## Pourquoi un signataire à politique plutôt qu'une clé dans le Hub

`AIMARKET_ESCROW_SUBMIT_STRATEGY=external` sort la clé du processus du Hub et, seul, cela
n'achète presque rien : le Hub envoie `{to, data, chainId, gas, value}` et un signataire naïf
signerait ce qu'on lui tend. Un Hub compromis muni du jeton demanderait
`USDC.transfer(attaquant, tout)`. Toute la valeur est dans les refus, énumérés comme règles
R1–R26 dans `escrow_signer/`.

Le risque résiduel qu'aucun signataire ne ferme, dit simplement : **un Hub compromis peut
toujours encaisser un travail non rendu**, dans la limite des plafonds de vitesse, avec des
signatures que les acheteurs ont réellement produites. Tous les champs vérifiés par le contrat
sont dans le digest du depositor, donc une telle requête est indiscernable d'une requête
légitime. Cela diminue avec des plafonds plus bas et des acheteurs qui signent par invocation
plutôt qu'à l'avance.

## Déploiement

```
scp -r escrow-signer/ signer-host:/root/escrow-signer/
cp .env.example .env      # sur l'hôte, chmod 600, avec la clé et le jeton
docker compose up -d --build
curl -s localhost:9500/health     # {"ok":true,"ready":true,...}
```

Puis, sur l'hôte du **Hub** :

```
cp deploy/escrow-signer-tunnel.service /etc/systemd/system/
systemctl enable --now escrow-signer-tunnel

cd /root/claudecode/aicom && ./scripts/deploy_hub_rebuild.sh --no-build \
  --set AIMARKET_ESCROW_SUBMIT_STRATEGY=external \
  --set AIMARKET_ESCROW_SIGNER_URL=http://127.0.0.1:9500/sign \
  --set AIMARKET_ESCROW_SIGNER_TOKEN="$(cat /root/.escrow-signer-token)" \
  --set AIMARKET_ESCROW_SUBMIT_CONFIRM=i-understand-this-moves-funds
```

`plan` d'abord, toujours : il construit le vrai calldata et le passe par `eth_call` contre
l'état réel, donc il répond « cela serait-il accepté maintenant ? » sans qu'aucune transaction
existe.

```
docker exec modelmarket-hub python -m aimarket_hub.escrow_bridge.cli plan
docker exec modelmarket-hub python -m aimarket_hub.escrow_bridge.cli submit --yes
```

Le quatrième cran est délibéré : dans aucune stratégie le Hub n'émet depuis le chemin de la
requête, donc le règlement régulier est une minuterie qui lance `submit --yes`, pas un fil
d'arrière-plan.

## Exploitation

- `GET /health` — disponibilité, l'adresse, et la raison d'un refus s'il refuse. Sans écriture.
- `GET /status` — les plafonds en vigueur et l'état du registre.
- `GET /receipt/<receipt_id>` — la réponse autoritaire à « qu'a réellement diffusé ce service ».
  Le Hub traite le hash renvoyé comme une preuve ; ici on peut le confronter.
- Il démarre **en refus** et y reste jusqu'à ce que le registre se vérifie, que la chaîne
  confirme qu'il est un hub autorisé, que le domain separator corresponde et que chaque ligne
  non résolue soit classée d'après la chaîne. Une file arrêtée vaut mieux qu'une signature non
  comptabilisée.

**Cette adresse est aussi la bénéficiaire.** `settleChannel` paie `ch.hub`, donc les recettes
s'accumulent ici et non dans la trésorerie. Les balayer est une action distincte de
l'opérateur.

## Plafonds

Tous en unités de base entières d'USDC (6 décimales). Chacun est obligatoire : une valeur
absente, nulle ou négative empêche le démarrage, et « sans limite » s'écrit `unlimited` et est
annoncé à chaque démarrage. Il n'y a délibérément pas de plafond « par passe » : le format de
la requête ne porte aucun identifiant de passe, et une passe déduite des silences se
réinitialise en réglant la cadence. Ce plafond reste dans le Hub.

Les plafonds en nombre ne doublonnent pas ceux en argent : brûler des reçus et moudre des
nonces ne coûte aucun USDC et n'est borné que par les compteurs. `SIGNER_CAP_FEE_WEI_24H` est
une troisième grandeur à part : les plafonds monétaires sont libellés dans le jeton, alors que
ce qui se dépense est l'ETH de cette clé.

## Tests

```
python -m pytest escrow-signer/tests -q      # 95 tests
```

`tests/test_wire.py` importe la classe `ExternalSigner` du Hub elle-même et la pilote contre un
vrai socket — y compris l'assertion qu'**aucune route ne répond jamais 3xx** : `urllib` suit
une redirection avec l'en-tête `Authorization` attaché, et une barre oblique finale de trop
deviendrait une divulgation du jeton. `tests/test_policy.py` est la table des refus, et chaque
cas vérifie que rien n'a été signé ni diffusé, pas seulement le code de statut.
