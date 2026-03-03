# gocrt-decoder

![Downloads](https://img.shields.io/github/downloads/leoberbert/gocrt-decoder/total?style=flat-square&color=D98E04)
![Lançamento GitHub](https://img.shields.io/github/v/release/leoberbert/gocrt-decoder?include_releases&style=flat-square)
![Problemas GitHub](https://img.shields.io/github/issues/leoberbert/gocrt-decoder?style=flat-square)
![Estrelas GitHub](https://img.shields.io/github/stars/leoberbert/gocrt-decoder?style=flat-square)
![Forks GitHub](https://img.shields.io/github/forks/leoberbert/gocrt-decoder?style=flat-square)


Ferramenta em Go para ler sessões do SecureCRT, decriptar `Password V2` e exportar para CSV com GUI em Fyne.

<img width="862" height="572" alt="image" src="https://github.com/user-attachments/assets/52a38c3f-90b6-4a92-8c1a-c39755366626" />

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
