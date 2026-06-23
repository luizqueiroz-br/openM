# Git Hooks do OpenM

Hooks compartilhados do projeto. **Não são ativados automaticamente** —
cada contribuidor precisa rodar uma vez:

```bash
git config core.hooksPath .githooks
```

## Hooks disponíveis

### `pre-commit`

**Protege o `Makefile`** contra deleção acidental.

Se algum arquivo staged for uma deleção do `Makefile`, o commit é
**bloqueado** com mensagem de aviso. Pra forçar a deleção (raro!):

```bash
git commit --no-verify
```

Também avisa se o `Makefile` não está presente na working tree
(situação anômala — em geral significa que foi deletado por engano).

## Por que o Makefile é crítico?

O `Makefile` contém todos os alvos de dev:

- `make install` — setup inicial
- `make db-up` / `make db-down` — Docker
- `make api` — Flask com hot-reload
- `make test` / `make test-auth` / `make test-api` — pytest
- `make debug` — servidor debug da issue #14
- `make lint` — flake8
- `make reset` — nuclear

Sem ele, contribuidores novos não conseguem subir o projeto.

## Como funciona tecnicamente?

`core.hooksPath` aponta Git pro diretório `.githooks/` em vez do default
`.git/hooks/`. Hooks commitados são distribuídos junto com o código —
todos os contribuidores ganham a mesma proteção automaticamente depois
de rodar o `git config` acima.

## Quem esqueceu de ativar?

Se você ver commits deletando `Makefile` sem aviso, o autor esqueceu
de ativar o hook. Peça educadamente que rode `git config core.hooksPath .githooks`.