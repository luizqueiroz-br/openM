# Issues — Brasil + Mercado Financeiro + Empresas (OpenM)

> **Status:** Rascunho para revisão. Não publicado no GitHub ainda.
> **Milestone:** `v1.0-brazil`
> **Estratégia:** 11 issues excepcionais (MVP) + 12 issues adiadas (v1.1+/v2.0).
> **Validação prévia:** discovery (estrutura), librarian (fontes públicas), oracle (modelagem e priorização).

---

## Sumário executivo

O OpenM é hoje uma plataforma OSINT de vínculos técnicos (DNS/IP/email/domínio) com 20 transforms e cobertura brasileira praticamente zero. Esta expansão adiciona:

- **Entidades de grafo BR** (Cnpj, Empresa, Estabelecimento, Socio, PessoaFisica, Ticker, Acao, CompanhiaAberta, Sancao, ProcessoJudicial, OrgaoSancionador, Municipio, Movimentacao).
- **Transforms** para BrasilAPI, BACEN SGS, Brapi, CVM, Portal da Transparência CGU.
- **LGPD Privacy Gate** com opt-in, audit e export/delete.
- **Template de issue** dedicado `brazil-osint.yml`.

Total estimado: **29 pontos** (1-2 mantenedores, ~2-3 meses em ritmo sustentável).

---

## Convenções

### Padrão de transform (resumo)
- Subclasse de `openm/core/transform.py:54` `Transform` com `@Transform.register`.
- Atributos: `name`, `display_name`, `input_types: List[str]`, `description`, `service_name`, `service_display`, `cache_ttl_seconds`.
- Método `_run(entity) -> TransformResult(entities, relationships)`.
- Service (`openm/services/<provider>_service.py`) com `get_key()` que consulta `ApiKey.service_name` + env var fallback.
- Cache via `transform_cache` (HIT/MISS/BYPASS).

### Padrão de entity (resumo)
- Subclasse de `openm/core/entity.py:7` `Entity`, setando `entity_type`.
- Registrada em `ENTITY_CLASSES` (`openm/core/entity.py:170`).
- `to_dict()` / `to_cytoscape()` herdados da base.

### Padrão de teste
- `unittest.mock.patch` direto na função chamada pelo transform.
- Fixtures versionadas em `tests/fixtures/brazil/` (a criar).
- `_FakeGraphManager` autouse via conftest; bypass em `@pytest.mark.e2e`.

### Padrão LGPD (obrigatório para qualquer transform com `data:pf`)
- Mascarar CPF/CNPJ/PIS/CNH em logs e respostas de API.
- Provenance obrigatório (`source` em `properties`).
- Opt-in flag `LGPD_PF_TRANSFORMS_ENABLED` (default `False`) — sem chave ON, transform de PF retorna `403 LGPD_PF_DISABLED`.
- Audit log de cada leitura (`target_type=PessoaFisica|Socio`, `action=read`).
- Cobertura de testes com mocks e fixtures (nunca chamar API real de PF em CI).

### Padrão de fixtures (obrigatório para qualquer transform BR)
- Arquivos em `tests/fixtures/brazil/<provider>/` com `last_verified: YYYY-MM-DD` e URL de origem.
- Modo "simulated" (key `OPENM_SIMULATED_BRAZIL=1`) lê fixture local, sem rede.
- CI lint que rejeita fixture sem `last_verified` > 180 dias.

### Padrão de documentação
- PT-BR em `docs/brazil-osint/<transform>.md` (público-alvo: pesquisador OSINT/CTI BR).
- README PT-BR (`README.md`) atualizado com quickstart "Como investigar uma empresa brasileira".
- Provenance UI: tooltip Cytoscape mostra `source` e `last_verified`.

---

## MVP — Phase 1: Fundações (4 issues)

---

### Issue #1 — Validador e formatador BR (CPF / CNPJ alfanumérico / PIS)

**Labels**: `area:backend`, `area:brazil-osint`, `enhancement`, `priority:high`, `i18n:pt-br`, `fixtures:required`, `lgpd:required`.

#### Resumo
Módulo utilitário `openm/core/br_validators.py` com classes `CpfValidator`, `CnpjValidator` (suporte alfanumérico + legado) e `PisValidator`, cada uma com métodos `validate(raw) -> bool`, `format(raw) -> str` (mascarado `***.456.789-**`), `checksum(raw) -> int` e `is_alfanumérico(raw) -> bool`. Reescrita dos algoritmos para suportar CNPJ alfanumérico (IN RFB 2.229/2024, julho/2026) com cálculo de DV por tabela ASCII (A=17, B=18, …). Documentação em `docs/brazil-osint/validators.md`.

#### Motivação
Sem validador unificado, cada transform de PF/PJ reinventa a regex e o checksum — e quebra silenciosamente em julho/2026 com o CNPJ alfanumérico. Hoje, o único validador de CNPJ implícito está em fixtures de teste.

#### Solução proposta
- `openm/core/br_validators.py` (novo): classes pur-Python sem dependência externa, ~300 linhas + 200 linhas de docstrings.
- `tests/test_br_validators.py` (novo): cobre CPF válido/inválido, CNPJ legado (14 dígitos numéricos), CNPJ alfanumérico (12 alfanuméricos + 2 DV), PIS, casos de borda (todos zeros, todos iguais, caracteres inválidos), vetores oficiais da Receita Federal.
- `docs/brazil-osint/validators.md` (novo): referência dos algoritmos e link para IN RFB 2.229/2024.

#### Critérios de aceitação
- [ ] Suporta CNPJ alfanumérico (julho/2026) e legado
- [ ] Cobre CPFs mascarados (`***.456.789-**`) — retorna `True` se o dígito verificador bate
- [ ] 100% de cobertura de testes (`pytest --cov=openm.core.br_validators`)
- [ ] Sem dependência nova em `requirements.txt`
- [ ] Documentação PT-BR
- [ ] Teste de regressão com CNPJ alfanumérico de exemplo conhecido

#### Esforço
2 (1-2 dias).

---

### Issue #2 — Máscara LGPD + log filter

**Labels**: `area:backend`, `area:security`, `area:brazil-osint`, `enhancement`, `priority:high`, `i18n:pt-br`, `lgpd:required`.

#### Resumo
Módulo `openm/core/lgpd.py` com utilitários `mask_cpf(raw)`, `mask_cnpj(raw)`, `mask_pis(raw)`, `mask_generic(value, kind)` e um `LoggingFilter` que mascara automaticamente qualquer string contendo padrão de CPF/CNPJ/PIS nos logs (registrado em `app.py`). Função `hash_pf(value) -> str` (SHA-256 truncado a 16 chars) para uso como chave de dedup sem expor o dado em cleartext.

#### Motivação
O OpenM trata dados de PF indiretamente via QSA da Receita, CEIS, DataJud etc. Hoje, se um CPF aparecer num log, fica em cleartext — risco LGPD direto. LGPD art. 46 ("medidas de segurança") e art. 18 (direitos do titular) exigem que o controlador minimize exposição.

#### Solução proposta
- `openm/core/lgpd.py` (novo): `mask_cpf`, `mask_cnpj`, `mask_pis`, `mask_generic`, `hash_pf`, `LoggingFilter` (substitui dígitos/letras por `*` mantendo tamanho).
- `openm/app.py`: registrar o `LoggingFilter` no `logging.root` durante `create_app()`.
- `tests/test_lgpd.py` (novo): cobre todos os formatos (com/sem pontuação, mascarado, alfanumérico), e garante que logs gerados em testes com CPF não vazam o cleartext (`caplog` snapshot).
- Atualizar `openm/core/audit.py` (linha 2): chamadas que logam `target_id` agora passam pelo `mask_generic` quando `target_type` ∈ {`PessoaFisica`, `Socio`, `Sancao`}.

#### Critérios de aceitação
- [ ] Nenhum log de teste contém CPF/CNPJ em cleartext (`grep -E '\d{3}\.\d{3}\.\d{3}-\d{2}' tests/` retorna vazio)
- [ ] `hash_pf` é determinístico e resistente a colisão (16 chars hex)
- [ ] Cobertura 100%
- [ ] Documentação PT-BR em `docs/brazil-osint/lgpd.md`

#### Esforço
2 (1-2 dias).

---

### Issue #3 — Entidades de grafo BR + registry

**Labels**: `area:backend`, `area:graph`, `area:brazil-osint`, `enhancement`, `priority:critical`, `i18n:pt-br`, `lgpd:required`.

#### Resumo
Adicionar ao `openm/core/entity.py:7-170` 13 subclasses de `Entity` (Cnpj, Empresa, Estabelecimento, Socio, PessoaFisica, PessoaJuridica, Ticker, Acao, CompanhiaAberta, Sancao, ProcessoJudicial, OrgaoSancionador, Municipio, Movimentacao) com `entity_type` próprio, validação no `__init__` (via `br_validators` da issue #1) e propriedades iniciais vazias. Registro em `ENTITY_CLASSES`. Migration Alembic **não** necessária (entidades vivem no Neo4j, não no Postgres).

#### Motivação
Sem entidades BR no grafo, não há destino para os novos transforms. Modelar agora define contratos para todas as issues seguintes.

#### Solução proposta
- `openm/core/entity.py`: adicionar 13 classes; cada uma com `entity_type` (string), `__init__` que valida o `value` (ex: `Cnpj.__init__` chama `CnpjValidator.validate`), e properties vazias + `last_verified` + `source`.
- `ENTITY_CLASSES` (linha 170): incluir as 13 novas classes.
- `tests/test_br_entities.py` (novo): cobre cada entidade isoladamente (validação, `to_dict`, `to_cytoscape`).
- Decisões de modelagem (ver "Decisões de modelagem" no fim deste doc).

#### Modelo de dados

```
Cnpj(value, properties: {tipo: matriz|filial, source})
  -[:IDENTIFICA]->
Estabelecimento(value=cnpj_completo, properties: {nome_fantasia, situacao, data_situacao, endereco: {logradouro, numero, cep, municipio_id, uf}, cnae_principal, cnae_secundarios, ie, telefone, email, source, last_verified})
  -[:PARTE_DE]->
Empresa(value=cnpj_raiz, properties: {razao_social, natureza_juridica, porte, capital_social, data_abertura, simples: {optante, data_opcao}, simei: {optante}, source, last_verified})

PessoaFisica(value=cpf_mascarado, properties: {nome, data_nascimento, faixa_etaria, situacao_cpf, source, last_verified})
PessoaJuridica(value=cnpj, properties: {razao_social, source, last_verified})

Socio(value, properties: {tipo: socio|administrador|procurador, percentual, data_entrada, cpf_representante_mascarado, qualificacao, source})
  -[:TEM_PAPEL]->
  -[:SOCIO_DE]->

Ticker (string, não nó) indexado em Acao.ticker
Acao(value=ticker, properties: {tipo: ON|PN, classe, codigo_isin, setor, segmento, source, last_verified})
  -[:PERTENCE_A]-> (empresa emitente)
CompanhiaAberta(value=cnpj, properties: {registro_cvm, situacao_registro, data_registro, categoria_registro, setor_b3, source, last_verified})
  -[:EMITE]-> Acao
  -[:MESMA_EMPRESA]-> Empresa

Sancao(value, properties: {tipo: CEIS|CNEP|CEPIM|CEAF, orgao_sancionador, data_inicio, data_fim, motivo, fundamentacao_legal, numero_processo, valor_multa, source, last_verified})
  -[:SANCIONADA_EM]->
  -[:APLICADA_POR]-> OrgaoSancionador

OrgaoSancionador(value, properties: {nome, sigla, esfera: federal|estadual|municipal, source})

Municipio(value=ibge_code, properties: {nome, uf, microrregiao, mesorregiao, lat, lng, source, last_verified})
  -[:LOCALIZA]->

ProcessoJudicial(value=numero_cnj, properties: {classe, assunto, valor_causa, orgao, data_distribuicao, segredo_justica: bool, source, last_verified})
  -[:TEM_MOVIMENTACAO]->
Movimentacao(value, properties: {data, tipo, texto, complemento, fonte, source, last_verified})
```

#### Critérios de aceitação
- [ ] 13 entidades adicionadas a `ENTITY_CLASSES`
- [ ] Validação no `__init__` (CPF/CNPJ/IE/CNJ validados via `br_validators` da issue #1)
- [ ] Nenhum CPF/CNPJ armazenado em cleartext (sempre hash + máscara parcial)
- [ ] 100% cobertura de testes em `tests/test_br_entities.py`
- [ ] Documentação PT-BR em `docs/brazil-osint/entities.md` com diagrama ASCII das relações
- [ ] Sem migration Postgres (Neo4j-only)
- [ ] Atualizar `openm/api/entities.py:38,86,126` para aceitar os novos `entity_type` no POST/PATCH/DELETE

#### Esforço
5 (1-1,5 semanas).

---

### Issue #4 — Template de issue `brazil-osint.yml`

**Labels**: `area:docs`, `enhancement`, `priority:medium`, `i18n:pt-br`.

#### Resumo
Novo template `.github/ISSUE_TEMPLATE/brazil-osint.yml` (formato Issue Forms YAML com `type:`, `attributes.options`, `validations.required`) dedicado a entidades/transforms/fontes brasileiras. Substituir o uso direto de `transform.yml` para issues BR. Manter `transform.yml` para provedores genéricos.

#### Motivação
O checklist de uma issue BR difere materialmente do checklist de uma issue genérica: tipo de fonte (Receita/BACEN/CVM/...), camada de acesso, alvo PF/PJ, mascaramento LGPD, modo simulado, fixtures obrigatórias, documentação PT-BR. Forçar tudo isso dentro do `transform.yml` atual polui o template e gera issues mal-preenchidas.

#### Solução proposta
- `.github/ISSUE_TEMPLATE/brazil-osint.yml` (novo): Issue Form com os campos:
  - **Tipo de fonte** (dropdown, required): Receita Federal / BACEN / CVM / B3 / CGU / TSE / CNJ / IBGE / BrasilAPI / Outra
  - **Camada de acesso** (dropdown, required): aberto / autenticado / pago
  - **Alvo** (checkboxes, required): PF / PJ / conta / processo / bem / instrumento
  - **Mascaramento LGPD exigido?** (boolean, default true)
  - **Modo simulado disponível?** (boolean, default true)
  - **Rate limit específico BR** (text, optional)
  - **Documentação oficial da fonte** (url, required)
  - **Entidades de entrada aceitas** (checkboxes, required): todas as 24 entidades (existentes + novas)
  - **Entidades de saída produzidas** (textarea, required)
  - **Critérios de aceitação** (checkboxes, required): implementa BaseTransform BR / modo simulado / máscara LGPD / provenance / fixtures versionadas / testes pytest / README PT-BR
- Labels automáticas via `labels: ["area:brazil-osint", "enhancement", "status:in-review"]`.
- Atualizar `docs/contributing.md` (a criar) com referência ao novo template.

#### Critérios de aceitação
- [ ] Template visível no dropdown de "New issue" do GitHub
- [ ] Todos os campos `required: true` aparecem
- [ ] Labels automáticas atribuídas ao criar a issue
- [ ] PR de teste criando uma issue de exemplo (preview) e screenshot

#### Esforço
1 (1 dia).

---

## MVP — Phase 2: Transforms (4 issues)

---

### Issue #5 — Transform BACEN SGS Séries Macro

**Labels**: `area:transforms`, `area:brazil-osint`, `enhancement`, `priority:high`, `source:bacen`, `tier:open`, `fixtures:required`, `i18n:pt-br`, `data:public`.

#### Resumo
Transform `openm/transforms/bacen_sgs.py` com `BacenSGSTransform`. Input: `MacroSerie` (nova entidade em issue #3) com `value=<código_sgs>` (ex: `432` para Selic meta, `433` para IPCA, `12` para CDI, `1` para USD). Output: `IndicadorMacro` (nova entidade) com `value=<nome>_<código>`, properties `{valor, data, fonte: "BACEN SGS", source, last_verified}`. Service `openm/services/bacen_sgs_service.py` com `get_key()` retornando `None` (sem chave). Cache TTL: 6h (Selic/IPCA) a 24h (CDI/USD). Endpoint: `GET https://api.bcb.gov.br/dados/serie/bcdata.sgs.{codigo}/dados?formato=json&dataInicial=DD/MM/AAAA&dataFinal=DD/MM/AAAA`.

#### Motivação
BACEN SGS é a fonte primária para séries macroeconômicas do Brasil — sem chave, sem SLA quebrado, ~5 req/s tolerado, ODbL. É a melhor "válvula de escape" para enriquecer grafos com contexto (ex: variação cambial cruzando com transação suspeita).

#### Solução proposta
- `openm/transforms/bacen_sgs.py` (novo): `BacenSGSTransform` subclasse de `Transform`, `name="bacen_sgs"`, `display_name="BACEN SGS — Séries Macro"`, `input_types=["MacroSerie"]`, `cache_ttl_seconds=21600` (6h).
- `openm/services/bacen_sgs_service.py` (novo): método `fetch_serie(codigo, data_inicial, data_final) -> List[Dict]` chamando `http_get` de `openm/core/http_client.py:151`.
- Adicionar entidades `MacroSerie` e `IndicadorMacro` em `openm/core/entity.py` (já cobertas pela issue #3; se #3 não estiver pronta, criar stub local e mesclar depois).
- Fixtures: `tests/fixtures/brazil/bacen/sgs_432_selic.json`, `sgs_433_ipca.json` com 30 dias de dados + `last_verified`.
- `tests/test_bacen_sgs_transform.py` (novo): mocks + fixtures + caso de série inexistente.
- Documentação `docs/brazil-osint/bacen-sgs.md`.

#### Critérios de aceitação
- [ ] Implementa `BaseTransform` BR (com `source` em `properties`, fixtures, modo simulado)
- [ ] Trata rate-limit (HTTP 429 com backoff via `http_client`)
- [ ] Marca edges com `provenance: "bacen_sgs"`
- [ ] Modo simulado ativado por env var `OPENM_SIMULATED_BRAZIL=1`
- [ ] Testes com fixtures/mocks; pytest 100% verde
- [ ] Documentado no README PT-BR e em `docs/brazil-osint/bacen-sgs.md`
- [ ] Sem chave de API necessária

#### Esforço
2 (1-2 dias).

---

### Issue #6 — Transform BrasilAPI CEP

**Labels**: `area:transforms`, `area:brazil-osint`, `enhancement`, `priority:high`, `source:brasilapi`, `tier:open`, `fixtures:required`, `i18n:pt-br`, `data:public`.

#### Resumo
Transform `openm/transforms/brasilapi_cep.py` com `BrasilApiCepTransform`. Input: `Cep` (string, não entidade nova; tratado via `input_types=["Estabelecimento", "Cep"]`). Output: enriquece a entidade input com `properties.endereco` (logradouro, bairro, cidade, UF, IBGE, DDD) ou cria `Endereco` standalone + edge `(:Estabelecimento)-[:LOCALIZADO_EM]->(:Endereco)` + edge `(:Endereco)-[:EM]->(:Municipio)`. Service `openm/services/brasilapi_service.py` com `get_key()=None` (sem chave). Endpoint V2: `GET https://brasilapi.com.br/api/cep/v2/{cep}` (com coordenadas). Cache TTL: 7 dias (CEP raramente muda).

#### Motivação
CEP é o pivot geográfico mais comum em OSINT BR (cruzamento de endereços). BrasilAPI V2 agrega ViaCEP + Correios + OpenCEP, com coordenadas, sem chave. Mesma API já cobre municípios IBGE, então otimiza fundação para outras transforms (CNPJ, QSA).

#### Solução proposta
- `openm/transforms/brasilapi_cep.py` (novo).
- `openm/services/brasilapi_service.py` (novo): `lookup_cep(cep)`, `lookup_cnpj(cnpj)`, `lookup_ibge(codigo)`, `list_pix_participants()` (esqueleto para v1.1).
- Reusar fixture pattern da issue #5.
- Testes + documentação PT-BR.

#### Critérios de aceitação
- [ ] Aceita CEP com/sem pontuação (8 dígitos)
- [ ] Retorna erro estruturado para CEP inexistente (não crash)
- [ ] Cria `Municipio` automaticamente (geocoding reverso via IBGE no mesmo response)
- [ ] Modo simulado + fixtures
- [ ] Cache 7 dias (604800s)
- [ ] Documentação PT-BR

#### Esforço
2 (1-2 dias).

---

### Issue #7 — Transform BrasilAPI CNPJ

**Labels**: `area:transforms`, `area:brazil-osint`, `enhancement`, `priority:high`, `source:brasilapi`, `tier:open`, `fixtures:required`, `i18n:pt-br`, `lgpd:required`, `data:pj` (QSA expõe CPF mascarado).

#### Resumo
Transform `openm/transforms/brasilapi_cnpj.py` com `BrasilApiCnpjTransform`. Input: `Cnpj` (issue #3). Output: cria `Estabelecimento` + `Empresa` (se raiz) + N `Socio` + edge `(:Cnpj)-[:IDENTIFICA]->(:Estabelecimento)-[:PARTE_DE]->(:Empresa)` + edge `(:Socio)-[:SOCIO_DE]->(:Empresa)`. QSA: para cada sócio, cria `PessoaFisica` (se `tipo="PF"`) ou `PessoaJuridica` (se `tipo="PJ"`) + edge `(:Socio)-[:TEM_PAPEL]->(:Pessoa*)`. Service reusando `brasilapi_service.py` da issue #6. Cache TTL: 24h. Endpoint: `GET https://brasilapi.com.br/api/cnpj/v1/{cnpj}`.

#### Motivação
Este é o transform central da expansão BR. CNPJ é o pivot corporativo por excelência. BrasilAPI é a única fonte grátis com QSA, sem chave, com suporte a alfanumérico em adequação.

#### Solução proposta
- `openm/transforms/brasilapi_cnpj.py` (novo).
- Suporte a CNPJ alfanumérico (validação via `br_validators` issue #1).
- Mascarar todos os CPFs retornados no QSA via `lgpd.mask_cpf` (issue #2).
- Quando sócio for PJ (sócio corporativo), criar `PessoaJuridica` (cnpj mascarado) + edge `(:PessoaJuridica)-[:TEM_PAPEL]->(:Socio)`.
- Audit log de cada leitura (issue #11 cobre, mas classe `audit` deve ter flag).
- Fixtures: 3 CNPJs reais (matriz, filial, MEI optante) + QSA com mix PF/PJ + `last_verified`.
- Documentação PT-BR incluindo interpretação do QSA e da flag `simples.optante`.

#### Critérios de aceitação
- [ ] Cria no mínimo 1 Empresa, 1 Estabelecimento, N Sócios (N≥1 do QSA)
- [ ] Cria edges: IDENTIFICA, PARTE_DE, SOCIO_DE, TEM_PAPEL
- [ ] Mascaramento LGPD em QSA (CPFs)
- [ ] Modo simulado com fixtures
- [ ] Cache 24h
- [ ] Funciona com CNPJ alfanumérico (issue #1) e legado
- [ ] Documentação PT-BR com exemplo end-to-end

#### Esforço
3 (3-4 dias).

---

### Issue #8 — Transform Brapi Cotações + Títulos Públicos

**Labels**: `area:transforms`, `area:brazil-osint`, `enhancement`, `priority:high`, `source:brapi`, `tier:registered`, `fixtures:required`, `i18n:pt-br`, `data:public`.

#### Resumo
Transform `openm/transforms/brapi_quote.py` com `BrapiQuoteTransform`. Input: `Acao` ou `TituloPublico` (issue #3) com `value=ticker` (ex: `PETR4`, `MXRF11`, `BTC-BRL`, `TESOURO_SELIC_2029`). Output: enriquece a entidade input com `properties.cotacao_atual`, `variacao_24h`, `volume`, `market_cap`, `p_l`, `p_vp`, `dividend_yield`, `preco_justo_brapi`, `governmentBonds` (TD). Service `openm/services/brapi_service.py` com `get_key()` consultando `ApiKey.service_name="brapi"` + env var `BRAPI_TOKEN` fallback. Endpoint: `GET https://brapi.dev/api/quote/{ticker}`. Cache TTL: 30min (próximo do delay grátis do Brapi) + alerta em 80% do `rate_limit_per_day`.

#### Motivação
Brapi é a melhor opção BR para cotações + fundamentais. Plano grátis (15k req/mês, 30 min delay) é suficiente para OSINT não-freqüente. SDK MIT + documentação PT-BR + suporte BR. Inclui Tesouro Direto no mesmo endpoint (`governmentBonds`).

#### Solução proposta
- `openm/transforms/brapi_quote.py` (novo).
- `openm/services/brapi_service.py` (novo): `get_key()` com fallback; contador de uso; método `quote(ticker) -> Dict`.
- Adicionar tracking `usage_count` para alerta em 80% (já existe no `ApiKey`; só precisamos hookar no `run_transform` endpoint).
- Adicionar painel admin de chaves BR (sub-issue do template ou criar issue própria na v1.1).
- Fixtures: 5 tickers (PETR4, MXRF11, IVVB11, BTC-BRL, TESOURO_SELIC_2029) com `last_verified`.
- Documentação PT-BR cobrindo limites, plano grátis, e exemplos de uso.

#### Critérios de aceitação
- [ ] Lê chave de `ApiKey` (priority) e env `BRAPI_TOKEN` (fallback)
- [ ] Trata plano grátis (15k req/mês) e erro 429 com backoff
- [ ] Enriquece `Acao` com cotação + fundamentalistas
- [ ] Enriquece `TituloPublico` com taxa/PU via `governmentBonds`
- [ ] Alerta visual em admin view quando `usage_count > 0.8 * rate_limit_per_day`
- [ ] Modo simulado + fixtures
- [ ] Documentação PT-BR

#### Esforço
3 (3-4 dias).

---

## MVP — Phase 3: Transforms avançados + LGPD (3 issues)

---

### Issue #9 — Transform CVM Cadastro Companhias Abertas

**Labels**: `area:transforms`, `area:brazil-osint`, `enhancement`, `priority:medium`, `source:cvm`, `tier:open`, `fixtures:required`, `i18n:pt-br`, `data:public`.

#### Resumo
Transform `openm/transforms/cvm_cias_abertas.py` com `CvmCiasAbertasTransform`. Input: `Cnpj`. Output: cria `CompanhiaAberta` (issue #3) com `properties: {registro_cvm, situacao_registro, data_registro, categoria_registro, setor_b3, denominação_comercial, nomes_comerciais_historicos}` + edge `(:CompanhiaAberta)-[:MESMA_EMPRESA]->(:Empresa)` (se Empresa já existir no grafo) + edge `(:CompanhiaAberta)-[:EMITE]->(:Acao)` (uma por ação listada). Service `openm/services/cvm_service.py` com `get_key()=None` (sem chave). Endpoint: `GET https://dados.cvm.gov.br/api/3/action/package_show?id=cias-abertas-informacao-cadastral` para resolver URL do CSV (CKAN pode renomear), depois download direto do CSV + parser. Cache TTL: 7 dias (cadastro muda raramente).

#### Motivação
CVM é a fonte primária para classificar uma Empresa como companhia aberta e seus dados regulatórios. Cruzar com Receita Federal (issue #7) entrega a visão completa de "esta empresa é aberta, atua em X setor, é registrada desde Y, foi sancionada em Z".

#### Solução proposta
- Wrapper que resolve URL atual do CSV via `package_show` (cache 30 dias) — defesa contra renomeação de datasets.
- Service `cvm_service.py` com `fetch_cias_abertas() -> Iterator[Dict]` (streaming CSV para não carregar 100MB+ em memória).
- Match por CNPJ raiz.
- Fixtures: CSV com 5 companhias + `last_verified`.
- Documentação PT-BR com interpretação de `categoria_registro` (A, B, ...) e ligação com `setor_b3`.

#### Critérios de aceitação
- [ ] Resolve URL atual via CKAN (com cache 30d)
- [ ] Match por CNPJ raiz (8 primeiros dígitos)
- [ ] Cria `CompanhiaAberta` + edges
- [ ] Trata "empresa não é companhia aberta" (response vazio, sem erro)
- [ ] Modo simulado com CSV fixture
- [ ] Documentação PT-BR

#### Esforço
3 (3-4 dias).

---

### Issue #10 — Transform Portal da Transparência — Sanções (CEIS/CNEP/CEPIM)

**Labels**: `area:transforms`, `area:brazil-osint`, `enhancement`, `priority:medium`, `source:cgu`, `tier:registered`, `fixtures:required`, `i18n:pt-br`, `lgpd:required`, `data:pf` (CNEP pode expor PF), `data:pj`.

#### Resumo
Transform `openm/transforms/cgu_sancoes.py` com `CguSancoesTransform`. Input: `Cnpj` ou `PessoaFisica` (CPF mascarado). Output: lista de `Sancao` (issue #3) + edge `(:PessoaFisica|Empresa)-[:SANCIONADA_EM]->(:Sancao)-[:APLICADA_POR]->(:OrgaoSancionador)`. Service `openm/services/cgu_service.py` com `get_key()` consultando `ApiKey.service_name="cgu_transparencia"` (cadastro de e-mail em `https://portaldatransparencia.gov.br/api-de-dados/cadastrar-email`). Endpoints: `GET https://api.portaldatransparencia.gov.br/ceis?cnpjSancionado=...` e `.../cnep?cnpjSancionado=...` e `.../cepim?cnpjSancionado=...`. Cache TTL: 24h. **Gate LGPD**: se input for `PessoaFisica` e `LGPD_PF_TRANSFORMS_ENABLED=False`, retornar `403 LGPD_PF_DISABLED`.

#### Motivação
CEIS/CNEP/CEPIM são os cadastros oficiais de empresas/pessoas sancionadas no Brasil (inidôneas, punidas, impedidas). Cruzar com Receita Federal e CVM entrega a posição final de "compliance de uma empresa".

#### Solução proposta
- `openm/transforms/cgu_sancoes.py` (novo): itera os 3 endpoints (CEIS, CNEP, CEPIM) em paralelo.
- `openm/services/cgu_service.py` (novo): `get_key()` retornando token do `ApiKey`; métodos `fetch_ceis(cnpj)`, `fetch_cnep(cnpj)`, `fetch_cepim(cnpj)`.
- Mascarar CPF retornado em CNEP via `lgpd.mask_cpf` (issue #2).
- Audit log de cada leitura (issue #11).
- Gate LGPD no início do `_run`.
- Fixtures: 3 sanções (1 CEIS, 1 CNEP, 1 CEPIM) com `last_verified`.
- Documentação PT-BR explicando diferença entre CEIS/CNEP/CEPIM.

#### Critérios de aceitação
- [ ] Gate LGPD para `PessoaFisica` (retorna 403 se flag OFF)
- [ ] Cria 1+ `Sancao` por resposta não-vazia
- [ ] Cria `OrgaoSancionador` único por tipo (CGU, CGU, CGU por padrão; configurável)
- [ ] Mascaramento LGPD em qualquer CPF retornado
- [ ] Modo simulado + fixtures
- [ ] Documentação PT-BR

#### Esforço
3 (3-4 dias).

---

### Issue #11 — LGPD Privacy Gate (audit log + opt-in PF + banner + data export)

**Labels**: `area:backend`, `area:security`, `area:brazil-osint`, `enhancement`, `priority:high`, `i18n:pt-br`, `lgpd:required`.

#### Resumo
Implementar 3 componentes integrados:

1. **Config flag** em `openm/config.py`: `LGPD_PF_TRANSFORMS_ENABLED: bool = False` (default OFF; precisa ser explicitamente habilitado). Adicionar `.env.example` com a chave.
2. **Endpoint LGPD**:
   - `GET /api/lgpd/export?cpf_mask=***.456.789-**` → retorna JSON com todos os nós/arestas do grafo que contêm esse CPF mascarado + todas as entradas do `AuditLog` que referenciam esse CPF.
   - `DELETE /api/lgpd/purge?cpf_mask=***.456.789-**` → remove nós/arestas e anonimiza entradas de audit log (substitui CPF por hash irreversível, mantendo timestamp e action para fins de auditoria interna).
   - Ambos protegidos por `@require_role("admin")` + audit log da própria operação.
3. **Audit log estendido** em `openm/core/audit.py`: nova action `LGPD_DATA_ACCESS` com `metadata.pf_data=True`; consultar via `GET /api/audit?action=LGPD_DATA_ACCESS` para DPO. Retention própria (separada) configurável via `LGPD_AUDIT_RETENTION_DAYS` (default 365).
4. **Banner mínimo no frontend** (`openm/frontend/templates/index.html`): se `LGPD_PF_TRANSFORMS_ENABLED=True` e a investigação contém `PessoaFisica` ou `Socio`, exibir banner "Esta investigação trata dados pessoais (LGPD). Acesso registrado em audit log."

#### Motivação
LGPD art. 18 garante direito de eliminação; art. 37 exige registro de operações de tratamento; art. 46 exige medidas de segurança. Sem opt-in + audit + export/delete, manter OpenM em produção com dados de PF expõe o mantenedor juridicamente.

#### Solução proposta
- `openm/config.py:10-77` adicionar 2 chaves.
- `openm/api/lgpd.py` (novo) — Blueprint com 2 rotas + `@require_role("admin")`.
- `openm/core/audit.py:2` estender `ACTION_LGPD_DATA_ACCESS` + `log_pf_access(user_id, target_type, target_id, action)`.
- `openm/frontend/static/js/inspector.js` — exibir banner quando grafo contém PF.
- `tests/test_lgpd_gate.py` (novo): cobre opt-in OFF (default), opt-in ON, export, purge, audit log.
- Documentação PT-BR em `docs/brazil-osint/lgpd-gate.md` com fluxo "DSR (data subject request) em 5 passos".

#### Critérios de aceitação
- [ ] Default OFF (transforms de PF retornam 403)
- [ ] `/api/lgpd/export` retorna JSON com nós + audit entries
- [ ] `/api/lgpd/purge` remove nós e anonimiza audit log
- [ ] Audit log tem retention própria (`LGPD_AUDIT_RETENTION_DAYS`)
- [ ] Banner aparece quando investigação contém PF/Socio
- [ ] Documentação PT-BR com DSR workflow
- [ ] 100% cobertura de testes

#### Esforço
3 (3-4 dias).

---

## Issues adiadas — v1.1+ (12 issues, cortar do MVP)

| # v1.1 | Título | Razão | Esforço |
|---|---|---|---|
| A1 | Validador PIS isolado | Já contemplado em #1 (MVP) | 1 |
| A2 | Transform BrasilAPI IBGE lookup | Já vem dentro de #6 (CEP V2 retorna IBGE) | 1 |
| A3 | Transform BrasilAPI PIX Participants | Nicho, baixa demanda, 1 chamada/ano | 2 |
| A4 | Transform TSE — Candidatos e Bens | LGPD pesado, auth instável, dados fragmentados | 5 |
| A5 | Transform DataJud CNJ — Metadados de Processo | Requer API Key CNJ + dados massivos; LGPD | 5 |
| A6 | Transform CoinGecko Cripto | Não-BR-specific, demo key proíbe produção; Brapi cobre | 2 |
| A7 | Painel admin de chaves BR | UI; depende de auth de usuário maduro | 3 |
| A8 | Filtros salvos por investigação | UI polish | 2 |
| A9 | Agrupamento visual (clusters Cytoscape) | Cytoscape já agrupa nativamente; 30 linhas | 1 |
| A10 | Export CSV/XLSX de entidades e relações | UI feature sem blocker | 3 |
| A11 | Heatmap de risco (score agregado) | Requer 3+ transforms maduros | 5 |
| A12 | Modo bulk / CLI para CNPJ (job queue) | Requer Celery/RQ + infra nova | 5 |

**Total adiado**: 35 pontos (≈ outro MVP completo; tratar como milestone v1.1).

---

## Issues adiadas — v2.0 (pagas, não OSS core)

| # v2.0 | Título | Observação |
|---|---|---|
| B1 | Transform Serpro ConectaGov CNPJ (oficial, contrato + e-CNPJ) | Documentar no README como alternativa paga; não integrar ao core |
| B2 | Transform Escavador processos (busca por CPF/CNPJ) | Idem |
| B3 | Transform Brapi Pro/paid tier | Idem |
| B4 | Snapshot temporal de Empresa (histórico de alterações) | YAGNI forte; versionamento adiciona 30% de complexidade |

---

## Decisões de modelagem (registradas)

Adotadas no MVP (issue #3) e refletidas em todas as transforms acima.

1. **`Cnpj` é entidade fraca; `Empresa` é a entidade forte.** CNPJ nunca muda; situação/QSA mudam. Tratar Cnpj como identificador puro permite deduplicação entre BrasilAPI, CVM, Serpro.
2. **`PessoaFisica` separada de `PessoaJuridica`; `Socio` é entidade-relação.** LGPD manda segregar PF/PJ. CPF sempre hash + máscara parcial (`***.456.789-**`).
3. **`Ticker` é string, não nó.** Indexado em `Acao.ticker`. Criar nó seria over-engineering.
4. **`ProcessoJudicial.Movimentacao` são entidades filhas**, não array. Permite pivotar por juiz, data, tipo.
5. **`Sancao` é nó, não edge.** Vigência, tipo, motivo mudam; edge vira pesadelo de update. Criar `OrgaoSancionador` como entidade habilita "todas sanções aplicadas pelo TCU".
6. **`Cep` permanece como string em `Estabelecimento`; `Municipio` é entidade (IBGE).** Geocoding reverso via IBGE no response do BrasilAPI V2.
7. **`CompanhiaAberta` é nó separado** com property `cnpj`, ligado por `:MESMA_EMPRESA -> Empresa` e `:EMITE -> Acao`. Permite queries "todas companhias abertas" sem cruzar Empresa.
8. **Provenance obrigatório** em todas as entidades BR: property `source` (string) + `last_verified` (ISO 8601) + edge `:MENTIONED_IN` quando múltiplas fontes.

---

## Roteiro de publicação

### Ordem de merge (sugestão para 1-2 mantenedores)

| Semana | Issues | Marco |
|---|---|---|
| 1 | #4, #1 | Template + validador (release patch `0.X+1`) |
| 2 | #2, #3 | Máscara LGPD + entidades BR (release minor `0.X+1`) |
| 3 | #5, #6 | BACEN + BrasilAPI CEP (release minor `0.X+2`) |
| 4 | #7 | BrasilAPI CNPJ (release minor `0.X+3` — feature de destaque) |
| 5 | #8 | Brapi (release minor `0.X+4`) |
| 6 | #9 | CVM Companhias Abertas (release minor `0.X+5`) |
| 7 | #10 | CGU Sanções (release minor `0.X+6`) |
| 8 | #11 | LGPD Privacy Gate (release `v1.0-brazil`) |

### Ações concretas para o mantenedor

1. **Criar milestone** `v1.0-brazil` no GitHub.
2. **Criar label** `area:brazil-osint` (e as outras: `data:pf`, `data:pj`, `data:public`, `tier:open`, `tier:registered`, `tier:commercial`, `lgpd:required`, `fixtures:required`, `i18n:pt-br`, `source:brasilapi`, `source:brapi`, `source:bacen`, `source:cvm`, `source:cgu`).
3. **Abrir as 11 issues** com os títulos, labels e descrições deste documento. Usar o template `brazil-osint.yml` (issue #4) para abrir as 10 seguintes.
4. **Não publicar** as 12 issues adiadas agora — apenas documentadas neste arquivo para roadmap futuro.

---

## Métricas de sucesso do MVP

- 11 issues fechadas em 8 semanas (ritmo sustentável).
- 100% cobertura de testes nos módulos novos (`br_validators`, `lgpd`, entidades BR, transforms BR).
- 0 vazamento de CPF/CNPJ em logs de teste (verificado por `grep` no CI).
- README PT-BR atualizado com seção "Como investigar uma empresa brasileira" (5 cliques do zero ao grafo enriquecido).
- Pelo menos 1 release `v1.0-brazil` publicado com vídeo demo ou GIF.

---

> **Última atualização**: gerado a partir de `~/dev/osint-projetc/.slim/deepwork/expansao-brasil-mercado-financeiro.md` após discovery (explorer), pesquisa de APIs (librarian) e revisão estratégica (oracle).
