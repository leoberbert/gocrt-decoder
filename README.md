# gocrt-decoder

Ferramenta em Go para ler sessões do SecureCRT, decriptar `Password V2` e exportar para CSV com GUI em Fyne.

## Requisitos

- Go 1.23+
- Dependências do Fyne para Linux desktop (GTK/OpenGL)

## Baixar e executar (binário pronto)

### Linux

1. Acesse a página de releases:
   - https://github.com/leoberbert/gocrt-decoder/releases
2. Baixe `gocrt-decoder-linux-amd64.zip`.
3. Extraia o arquivo.
4. No terminal, entre na pasta extraída e execute:

```bash
chmod +x gocrt-decoder
./gocrt-decoder
```

### Windows

1. Acesse a página de releases:
   - https://github.com/leoberbert/gocrt-decoder/releases
2. Baixe `gocrt-decoder-windows-amd64.zip`.
3. Extraia o arquivo.
4. Execute `gocrt-decoder.exe` com duplo clique.

## Gerar binários no GitHub Actions

- Workflow: `.github/workflows/packages.yml`
- Build manual: **Actions > Build Packages > Run workflow**
- Publicação em Releases: acontece ao enviar uma tag `v*` (ex.: `v1.0.0`)

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

## Créditos

- Leonardo Berbert
- Repositório: https://github.com/leoberbert/gocrt-decoder
