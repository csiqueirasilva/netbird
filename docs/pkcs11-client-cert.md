# mTLS ao IdP com a chave num token de hardware (PKCS#11)

## O problema

O cliente já sabe apresentar certificado ao IdP no `/token`:

```go
// client/internal/auth/pkce_flow.go
cert := p.providerConfig.ClientCertPair
if cert != nil { /* mTLS ao IdP */ }
```

Mas o par só pode vir de arquivo:

```go
// client/internal/profilemanager/config.go
cert, err := tls.LoadX509KeyPair(config.ClientCertPath, config.ClientCertKeyPath)
```

Isso exclui todo token de hardware, porque a chave é marcada `never extractable`
— não existe arquivo para apontar, e não pode existir. Justamente a propriedade
pela qual o token foi comprado é a que impede seu uso aqui.

Consequência prática: quem quiser exigir mTLS no endpoint de token do IdP precisa
escolher entre exigir de todos (e quebrar a inscrição por CLI) ou não exigir de
ninguém. Com certificado em arquivo, a chave volta a ser copiável, e o modelo de
ameaça deixa de ser "roubaram o token" e passa a ser "copiaram um arquivo".

## O que esta mudança faz

Acrescenta uma origem alternativa para o mesmo `tls.Certificate`: o token.

```
PKCS11:
  ModulePath:  /usr/lib/libeTPkcs11.so
  TokenSerial: 02f1ba64
  ObjectLabel: csiqueira-estacao
  Pin:         ****
```

A chave privada nunca é lida. `tls.Certificate.PrivateKey` recebe um
`crypto.Signer` que delega a assinatura ao token — o que atravessa a fronteira
PKCS#11 é a assinatura, não a chave.

Nada muda para quem já usa `ClientCertPath`/`ClientCertKeyPath`: o caminho por
arquivo continua idêntico e é o padrão quando `PKCS11` não está preenchido.

## Decisões de projeto

**Seleção por serial, não por label.** Tokens do mesmo fabricante repetem label —
todo eToken 5110 sai de fábrica como `5XPIN-eToken` — e o índice de slot muda a
cada replug. Serial é o único identificador estável.

**O certificado vem do token também**, não de um PEM ao lado. Um lugar só para
configurar, e nada para dessincronizar.

**Erro de assinatura é embrulhado com contexto.** Token desplugado no meio da
sessão falha com mensagem que diz isso, em vez de um erro genérico vindo de
dentro da pilha TLS.

## Estado

Implementado e com teste da validação de configuração. **A assinatura em si
ainda não foi exercitada contra hardware** — depende de token plugado e de
`crypto11` nas dependências. Testado contra: SafeNet eToken 5110 SC (pendente).

## Alternativas consideradas

**Certificado de máquina em arquivo.** Mais simples, e é o correto quando a
identidade é *da máquina* — inclusive é o que o próprio WireGuard faz com a chave
dele. Não serve quando o requisito é "a pessoa, com o token na mão, autoriza esta
inscrição".

**Proxy TLS local com engine PKCS#11** (stunnel e afins). Não exige mudança no
netbird, mas exige apontar o `TokenEndpoint` para localhost — e essa configuração
vem do management, é global, e afetaria todos os clientes.
