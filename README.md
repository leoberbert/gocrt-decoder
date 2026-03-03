# gocrt-decoder

Ferramenta em Go para ler sessões do SecureCRT, decriptar `Password V2` e exportar para CSV com GUI em Fyne.

## Requisitos

- Go 1.23+
- Dependências do Fyne para Linux desktop (GTK/OpenGL)

## Executar

```bash
go mod tidy
go run .
```

## Como usar

1. Clique em **Selecionar pasta** e escolha o diretório `Sessions` do SecureCRT.
2. Clique em **Selecionar destino CSV** e escolha o arquivo de saída.
3. Clique em **Exportar CSV**.

## CSV gerado

Colunas exportadas:

- `name`
- `hostname`
- `username`
- `port`
- `password` (decriptado quando possível)
- `source_file`

## Build de pacotes (GitHub Actions)

- Workflow: `.github/workflows/packages.yml`
- Gera pacotes `.zip` para:
  - Linux (`gocrt-decoder-linux-amd64.zip`)
  - Windows (`gocrt-decoder-windows-amd64.zip`)
- Pode ser executado de duas formas:
  - Manualmente via **Actions > Build Packages > Run workflow**
  - Automaticamente ao criar/push de tag `v*` (ex: `v1.0.0`)
- Em tags `v*`, também publica os `.zip` na página de **Releases**.

## Créditos

- Leonardo Berbert
- Repositório: https://github.com/leoberbert/gocrt-decoder
