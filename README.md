# Documentação do *Software* "ecutils"

## Nome do *Software*
**ecutils**

## Versão do *Software*
**1.1.0**

## Descrição do *Software*

O *ecutils* é uma aplicação de criptografia que oferece uma variedade de recursos e funcionalidades para operações relacionadas a Curvas Elípticas. Este *software* foi projetado para atender às necessidades de profissionais de segurança cibernética, desenvolvedores de *software* e qualquer pessoa que exija operações de criptografia de alto nível em suas atividades.

## Autor

* **Isak Paulo de Andrade Ruas** - Especialista em criptografia de Curvas Elípticas

## Finalidade

O *ecutils* tem como objetivo principal facilitar a execução de operações criptográficas avançadas usando Curvas Elípticas, garantindo a segurança e a privacidade dos dados.

## Características Principais

* **Geração de Curvas Elípticas:** O *software* permite a definição e criação de novas Curvas Elípticas, com a flexibilidade de especificar coeficientes, coordenadas e outros parâmetros essenciais.

* **Operações de Curva Elíptica:** Comandos como adição de pontos, multiplicação escalar e operações de ponto são suportados, tornando possível realizar cálculos complexos de criptografia.

* **Suporte a Protocolos de Segurança:** O *ecutils* oferece suporte a uma variedade de protocolos de segurança baseados em Curva Elíptica, como Diffie-Hellman, Assinatura Digital e o protocolo Massey–Omura.

## Descrições dos comandos do *software*

Aqui estão as descrições detalhadas dos comandos disponíveis no *software* *ecutils*:

##  Comandos gerais
### -info
Mostrar informações sobre a compilação e a versão do programa

### -license
Mostrar informações sobre a licença do programa

## Operações de Curva Elíptica

### -ec
Este comando ativa as operações em Curvas Elípticas.

### -ec-define
Este comando ativa a definição de uma nova Curva Elíptica.

### -ec-define-a string
Este comando permite definir o coeficiente 'a' da Curva Elíptica em formato hexadecimal.

### -ec-define-b string
Este comando permite definir o coeficiente 'b' da Curva Elíptica em formato hexadecimal.

### -ec-define-gx string
Este comando permite definir a coordenada x do ponto base 'G' na Curva Elíptica em formato hexadecimal.

### -ec-define-gy string
Este comando permite definir a coordenada y do ponto base 'G' na Curva Elíptica em formato hexadecimal.

### -ec-define-h string
Este comando permite definir o cofator 'h' da Curva Elíptica em formato hexadecimal.

### -ec-define-n string
Este comando permite definir a ordem 'n' do ponto base 'G' na Curva Elíptica em formato hexadecimal.

### -ec-define-p string
Este comando permite definir o módulo primo 'p' da Curva Elíptica em formato hexadecimal.

### -ec-dot
Este comando realiza a adição dos pontos P e Q na Curva Elíptica e retorna o resultado em valores hexadecimais.

### -ec-dot-px string
Este comando especifica a coordenada x de P.

### -ec-dot-py string
Este comando especifica a coordenada y de P.

### -ec-dot-qx string
Este comando especifica a coordenada x de Q.

### -ec-dot-qy string
Este comando especifica a coordenada y de Q.

### -ec-get string
Este comando identifica a Curva Elíptica para operações. Curvas suportadas: secp192k1, secp192r1, secp224k1, secp224r1, secp256k1, secp256r1, secp384r1, secp521r1.

### -ec-trapdoor
Este comando realiza a operação de multiplicação escalar do Ponto G na Curva Elíptica.

### -ec-trapdoor-gx string
Este comando especifica a coordenada x do Ponto G.

### -ec-trapdoor-gy string
Este comando especifica a coordenada y do Ponto G.

### -ec-trapdoor-k string
Especifica o escalar K em formato hexadecimal. (padrão "B")

## Protocolo de Troca de Chave de Curva Elíptica Diffie Hellman (ECDH)

### -ecdh
Este comando ativa o protocolo de Troca de Chave de Curva Elíptica Diffie Hellman (ECDH).

### -ecdh-ec-define
Este comando ativa a definição de uma nova Curva Elíptica para ECDH.

### -ecdh-ec-define-a string
Este comando permite definir o coeficiente 'a' para a nova curva em formato hexadecimal.

### -ecdh-ec-define-b string
Este comando permite definir o coeficiente 'b' para a nova curva em formato hexadecimal.

### -ecdh-ec-define-gx string
Este comando permite definir a coordenada x do ponto base 'G' para a nova curva em formato hexadecimal.

### -ecdh-ec-define-gy string
Este comando permite definir a coordenada y do ponto base 'G' para a nova curva em formato hexadecimal.

### -ecdh-ec-define-h string
Este comando permite definir o cofator 'h' da nova curva em formato hexadecimal.

### -ecdh-ec-define-n string
Este comando permite definir a ordem 'n' do ponto base 'G' para a nova curva em formato hexadecimal.

### -ecdh-ec-define-p string
Este comando permite definir o módulo primo 'p' da nova curva em formato hexadecimal.

### -ecdh-ec-get string
Este comando identifica a Curva Elíptica para uso no protocolo ECDH. Curvas suportadas: secp192k1, secp192r1, secp224k1, secp224r1, secp256k1, secp256r1, secp384r1, secp521r1.

### -ecdh-get-public-key
Este comando recupera a chave pública para o protocolo ECDH e retorna o resultado em valores hexadecimais.

### -ecdh-private-key string
Este comando especifica a chave privada para o protocolo ECDH em formato hexadecimal.

### -ecdh-toshare
Este comando gera um canal de comunicação seguro, retornando um ponto comum em formato hexadecimal.

### -ecdh-toshare-public-key-px string
Este comando especifica a coordenada x da chave pública.

### -ecdh-toshare-public-key-py string
Este comando especifica a coordenada y da chave pública.

## Algoritmo de Assinatura Digital de Curva Elíptica (ECDSA)

### -ecdsa
Este comando ativa o Algoritmo de Assinatura Digital de Curva Elíptica (ECDSA).

### -ecdsa-ec-define
Se definido como verdadeiro, permite a definição de novos parâmetros personalizados de Curva Elíptica.

### -ecdsa-ec-define-a string
Este comando permite definir o coeficiente 'a' da nova Curva Elíptica em formato hexadecimal.

### -ecdsa-ec-define-b string
Este comando permite definir o coeficiente 'b' da nova Curva Elíptica em formato hexadecimal.

### -ecdsa-ec-define-gx string
Este comando permite definir a coordenada x do ponto base 'G' da nova Curva Elíptica em formato hexadecimal.

### -ecdsa-ec-define-gy string
Este comando permite definir a coordenada y do ponto base 'G' da nova Curva Elíptica em formato hexadecimal.

### -ecdsa-ec-define-h string
Este comando permite definir o cofator 'h' da nova Curva Elíptica em formato hexadecimal.

### -ecdsa-ec-define-n string
Este comando permite definir a ordem 'n' do ponto base 'G' da nova Curva Elíptica em formato hexadecimal.

### -ecdsa-ec-define-p string
Este comando permite definir o módulo primo 'p' da nova Curva Elíptica em formato hexadecimal.

### -ecdsa-ec-get string
Especifica a Curva Elíptica específica para ECDSA. Curvas suportadas: secp192k1, secp192r1, secp224k1, secp224r1, secp256k1, secp256r1, secp384r1, secp521r1.

### -ecdsa-get-public-key
Se definido como verdadeiro, recupera a chave pública para ECDSA como um par de valores hexadecimais PX e PY.

### -ecdsa-private-key string
Este comando especifica a chave privada para ECDSA em formato hexadecimal.

### -ecdsa-signature
Se definido como verdadeiro, gera uma assinatura ECDSA. Retorna os valores R e S da assinatura gerada em formato hexadecimal.

### -ecdsa-signature-message string
Este comando especifica a mensagem de origem a ser assinada, fornecida em formato hexadecimal.

### -ecdsa-verify-signature
Se definido como verdadeiro, habilita a função de verificação de assinatura ECDSA. Retorna 1 se a assinatura fornecida for válida e 0 caso contrário.

### -ecdsa-verify-signature-public-key-px string
Este comando especifica a coordenada x da Chave Pública usada para a verificação da assinatura ECDSA, fornecida em formato hexadecimal.

### -ecdsa-verify-signature-public-key-py string
Este comando especifica a coordenada y da Chave Pública usada para a verificação da assinatura ECDSA, fornecida em formato hexadecimal.

### -ecdsa-verify-signature-r string
Este comando especifica o valor 'R' da assinatura ECDSA a ser verificado, fornecido em formato hexadecimal.

### -ecdsa-verify-signature-s string
Este comando especifica o valor 'S' da assinatura ECDSA a ser verificado, fornecido em formato hexadecimal.

### -ecdsa-verify-signature-signed-message string
Este comando especifica a mensagem original que foi assinada com ECDSA, fornecida em formato hexadecimal.

## Codificação e Decodificação em Criptografia de Curva Elíptica

### -eck
Este comando ativa operações de codificação e decodificação em Criptografia de Curva Elíptica.

### -eck-decode
Este comando ativa a função de decodificação que converte um ponto na curva elíptica de volta para uma mensagem de string.

### -eck-decode-j string
Este comando especifica o 'invariante j' do ponto na curva elíptica, em formato hexadecimal, a ser decodificado.

### -eck-decode-px string
Este comando especifica a coordenada x do ponto na curva elíptica, em formato hexadecimal, a ser decodificado.

### -eck-decode-py string
Este comando especifica a coordenada y do ponto na curva elíptica, em formato hexadecimal, a ser decodificado.

### -eck-ec-define
Este comando permite a definição personalizada de uma Curva Elíptica.

### -eck-ec-define-a string
Este comando define 'a', o coeficiente da Curva Elíptica, em formato hexadecimal.

### -eck-ec-define-b string
Este comando define 'b', o coeficiente da Curva Elíptica, em formato hexadecimal.

### -eck-ec-define-gx string
Este comando define 'Gx', a coordenada x do ponto base 'G' na Curva Elíptica, em formato hexadecimal.

### -eck-ec-define-gy string
Este comando define 'Gy', a coordenada y do ponto base 'G' na Curva Elíptica, em formato hexadecimal.

### -eck-ec-define-h string
Este comando define 'h', o cofator da Curva Elíptica, em formato hexadecimal.

### -eck-ec-define-n string
Este comando define 'n', a ordem do ponto base 'G' na Curva Elíptica, em formato hexadecimal.

### -eck-ec-define-p string
Este comando define 'p', o módulo primo da Curva Elíptica, em formato hexadecimal.

### -eck-ec-get string
Este comando especifica a Curva Elíptica a ser usada para operações. Curvas suportadas: secp384r1, secp521r1.

### -eck-encoding-type
Este comando especifica o tipo de codificação a ser utilizado. Ele suporta as seguintes curvas para 'unicode': secp384r1 e secp521r1, e as seguintes curvas para 'ascii': secp192k1, secp192r1, secp256k1, secp256r1, secp384r1 e secp521r1. O valor padrão é 'unicode'.

### -eck-encode
Este comando ativa a função de codificação que converte uma mensagem de string em um ponto na curva elíptica. A saída está em formato hexadecimal.

### -eck-encode-message string
Este comando especifica a mensagem a ser codificada em um ponto na curva elíptica.

## Protocolo Massey–Omura de Curva Elíptica

### -ecmo
Este comando ativa o protocolo Massey–Omura de Curva Elíptica.

### -ecmo-decrypt
Este comando decodifica um ponto dado na Curva Elíptica em uma mensagem de string.

### -ecmo-decrypt-j string
Este comando especifica o 'invariante j' do ponto na Curva Elíptica. Deve estar em formato hexadecimal.

### -ecmo-decrypt-px string
Este comando especifica a coordenada x do ponto na Curva Elíptica a ser decodificado. Deve estar em formato hexadecimal.

### -ecmo-decrypt-py string
Este comando especifica a coordenada y do ponto na Curva Elíptica a ser decodificado. Deve estar em formato hexadecimal.

### -ecmo-decrypt-r string
Este comando especifica o 'r-signature' do ponto na Curva Elíptica. Deve estar em formato hexadecimal.

### -ecmo-decrypt-s string
Este comando especifica o 's-signature' do ponto na Curva Elíptica. Deve estar em formato hexadecimal.

### -ecmo-decrypt-toshare-public-key-px string
Este comando especifica a coordenada x da chave pública a ser usada para decodificação.

### -ecmo-decrypt-toshare-public-key-py string
Este comando especifica a coordenada y da chave pública a ser usada para decodificação.

### -ecmo-ec-define
Este comando ativa a criação de uma nova Curva Elíptica.

### -ecmo-ec-define-a string
Este comando define o coeficiente 'a' da Curva Elíptica em formato hexadecimal.

### -ecmo-ec-define-b string
Este comando define o coeficiente 'b' da Curva Elíptica em formato hexadecimal.

### -ecmo-ec-define-gx string
Este comando define 'Gx', a coordenada x do ponto base 'G' na Curva Elíptica, em formato hexadecimal.

### -ecmo-ec-define-gy string
Este comando define 'Gy', a coordenada y do ponto base 'G' na Curva Elíptica, em formato hexadecimal.

### -ecmo-ec-define-h string
Este comando define 'h', o cofator da Curva Elíptica, em formato hexadecimal.

### -ecmo-ec-define-n string
Este comando define 'n', a ordem do ponto base 'G' na Curva Elíptica, em formato hexadecimal.

### -ecmo-ec-define-p string
Este comando define 'p', o módulo primo 'p' da Curva Elíptica, em formato hexadecimal.

### -ecmo-eck-encoding-type
Este comando especifica o tipo de codificação a ser utilizado. Ele suporta as seguintes curvas para 'unicode': secp384r1 e secp521r1, e as seguintes curvas para 'ascii': secp192k1, secp192r1, secp256k1, secp256r1, secp384r1 e secp521r1. O valor padrão é 'unicode'.

### -ecmo-ec-get string
Este comando especifica a Curva Elíptica a ser usada para operações. Curvas suportadas: secp384r1, secp521r1.

### -ecmo-encrypt
Este comando criptografa uma mensagem de string em um ponto na Curva Elíptica. A saída está em formato hexadecimal.

### -ecmo-encrypt-message string
Este comando especifica a mensagem a ser criptografada.

### -ecmo-encrypt-toshare-public-key-px string
Este comando especifica a coordenada x da chave pública a ser usada para criptografia.

### -ecmo-encrypt-toshare-public-key-py string
Este comando especifica a coordenada y da chave pública a ser usada para criptografia.

### -ecmo-get-public-key
Este comando recupera a chave pública para o protocolo Massey–Omura. A saída está no formato Hex(PX) Hex(PY).

### -ecmo-private-key string
Este comando especifica a chave privada para o protocolo Massey–Omura de Curva Elíptica em formato hexadecimal.

## Exemplos de Utilização

Primeiro, vamos definir alguns parâmetros para utilização durante os testes:

```bash
#!/bin/bash

# Declara um array associativo chamado elliptic_curves para armazenar os parâmetros das curvas elípticas.
declare -A elliptic_curves

# Define os parâmetros das curvas elípticas no array elliptic_curves.
# Cada curva é identificada por um nome, como "secp192k1", e possui parâmetros como P, A, B, Gx, Gy, N e H.
elliptic_curves["secp192k1,P"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37"
elliptic_curves["secp192k1,A"]="0"
elliptic_curves["secp192k1,B"]="3"
elliptic_curves["secp192k1,Gx"]="DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D"
elliptic_curves["secp192k1,Gy"]="9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D"
elliptic_curves["secp192k1,N"]="FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D"
elliptic_curves["secp192k1,H"]="1"

elliptic_curves["secp192r1,P"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF"
elliptic_curves["secp192r1,A"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC"
elliptic_curves["secp192r1,B"]="64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1"
elliptic_curves["secp192r1,Gx"]="188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"
elliptic_curves["secp192r1,Gy"]="07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"
elliptic_curves["secp192r1,N"]="FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831"
elliptic_curves["secp192r1,H"]="1"

elliptic_curves["secp224k1,P"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D"
elliptic_curves["secp224k1,A"]="000000000"
elliptic_curves["secp224k1,B"]="000000005"
elliptic_curves["secp224k1,Gx"]="A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C"
elliptic_curves["secp224k1,Gy"]="7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5"
elliptic_curves["secp224k1,N"]="010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7"
elliptic_curves["secp224k1,H"]="1"

elliptic_curves["secp224r1,P"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001"
elliptic_curves["secp224r1,A"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE"
elliptic_curves["secp224r1,B"]="B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4"
elliptic_curves["secp224r1,Gx"]="B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"
elliptic_curves["secp224r1,Gy"]="BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"
elliptic_curves["secp224r1,N"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"
elliptic_curves["secp224r1,H"]="1"

elliptic_curves["secp256k1,P"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
elliptic_curves["secp256k1,A"]="00000000000000000"
elliptic_curves["secp256k1,B"]="00000000000000007"
elliptic_curves["secp256k1,Gx"]="79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
elliptic_curves["secp256k1,Gy"]="483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
elliptic_curves["secp256k1,N"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
elliptic_curves["secp256k1,H"]="0000000"

elliptic_curves["secp256r1,P"]="FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
elliptic_curves["secp256r1,A"]="FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"
elliptic_curves["secp256r1,B"]="5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
elliptic_curves["secp256r1,Gx"]="6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
elliptic_curves["secp256r1,Gy"]="4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
elliptic_curves["secp256r1,N"]="FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
elliptic_curves["secp256r1,H"]="1"

elliptic_curves["secp384r1,P"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"
elliptic_curves["secp384r1,A"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC"
elliptic_curves["secp384r1,B"]="B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"
elliptic_curves["secp384r1,Gx"]="AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"
elliptic_curves["secp384r1,Gy"]="3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"
elliptic_curves["secp384r1,N"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"
elliptic_curves["secp384r1,H"]="1"

elliptic_curves["secp521r1,P"]="01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
elliptic_curves["secp521r1,A"]="01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC"
elliptic_curves["secp521r1,B"]="0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"
elliptic_curves["secp521r1,Gx"]="00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"
elliptic_curves["secp521r1,Gy"]="011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"
elliptic_curves["secp521r1,N"]="01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"
elliptic_curves["secp521r1,H"]="1"

# Define uma lista de nomes de curvas elípticas para serem usados posteriormente.
curve_names=("secp192k1" "secp192r1" "secp224k1" "secp224r1" "secp256k1" "secp256r1" "secp384r1" "secp521r1")
```

### Testando EC

```bash
# Inicia a execução do script e exibe uma mensagem informativa.
echo "  >  Testando EC: ..."

# Obtém o tempo de início da execução do loop.
start_time=$(date +%s%N)

# Loop que itera sobre as curvas elípticas definidas.
for curve in "${curve_names[@]}"; do
    # Extrai o nome da curva (por exemplo, "secp192k1") da variável curve.
    curve_name="${curve%,*}"

    # Obtém os parâmetros da curva elíptica a partir do array elliptic_curves.
    P="${elliptic_curves[$curve_name,P]}"
    A="${elliptic_curves[$curve_name,A]}"
    B="${elliptic_curves[$curve_name,B]}"
    Gx="${elliptic_curves[$curve_name,Gx]}"
    Gy="${elliptic_curves[$curve_name,Gy]}"
    N="${elliptic_curves[$curve_name,N]}"
    H="${elliptic_curves[$curve_name,H]}"
    
    # Realiza uma operação de trapdoor com os parâmetros da curva e obtém o resultado em R.
    R=$(./ecutils -ec -ec-get "$curve_name" -ec-trapdoor -ec-trapdoor-k F -ec-trapdoor-gx "$Gx" -ec-trapdoor-gy "$Gy")

    # Realiza uma operação de definição de curva e trapdoor com os mesmos parâmetros e obtém o resultado em S.
    S=$(./ecutils -ec -ec-define -ec-define-p "$P" -ec-define-a "$A" -ec-define-b "$B" -ec-define-gx "$Gx" -ec-define-gy "$Gy" -ec-define-n "$N" -ec-define-h "$H" -ec-trapdoor -ec-trapdoor-k F -ec-trapdoor-gx "$Gx" -ec-trapdoor-gy "$Gy")

    # Compara os resultados R e S obtidos acima e verifica se eles são iguais.
    if [ "$R" != "$S" ]; then
        echo "  >  EC Erro: $R != $S"
        exit 1
    fi
    
    # Extrai as coordenadas X e Y do resultado R.
    Qx=$(echo "$R" | cut -d' ' -f1)
    Qy=$(echo "$R" | cut -d' ' -f2)
    
    # Realiza uma operação de ponto com as coordenadas extraídas e obtém o resultado em R.
    R=$(./ecutils -ec -ec-get "$curve_name" -ec-dot -ec-dot-px "$Gx" -ec-dot-py "$Gy" -ec-dot-qx "$Qx" -ec-dot-qy "$Qy")

    # Realiza uma operação de definição de curva e ponto com os mesmos parâmetros e obtém o resultado em S.
    S=$(./ecutils -ec -ec-define -ec-define-p "$P" -ec-define-a "$A" -ec-define-b "$B" -ec-define-gx "$Gx" -ec-define-gy "$Gy" -ec-define-n "$N" -ec-define-h "$H" -ec-dot -ec-dot-px "$Gx" -ec-dot-py "$Gy" -ec-dot-qx "$Qx" -ec-dot-qy "$Qy")

    # Compara os resultados R e S obtidos acima e verifica se eles são iguais.
    if [ "$R" != "$S" ]; then
        echo "  >  EC Erro: $R != $S"
        exit 1
    fi
done

# Obtém o tempo de término da execução do loop.
end_time=$(date +%s%N)

# Calcula o tempo total de execução do loop e exibe-o.
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Concluído, tempo de execução: ${execution_time} ms"
```

### Testando ECDH

```bash
# Exibe uma mensagem informativa indicando que os testes ECDH estão sendo executados.
echo "  >  Testando ECDH: ..."

# Obtém o tempo de início da execução do loop.
start_time=$(date +%s%N)

# Loop que itera sobre as curvas elípticas definidas.
for curve in "${curve_names[@]}"; do
    # Extrai o nome da curva (por exemplo, "secp192k1") da variável curve.
    curve_name="${curve%,*}"

    # Obtém os parâmetros da curva elíptica a partir do array elliptic_curves.
    P="${elliptic_curves[$curve_name,P]}"
    A="${elliptic_curves[$curve_name,A]}"
    B="${elliptic_curves[$curve_name,B]}"
    Gx="${elliptic_curves[$curve_name,Gx]}"
    Gy="${elliptic_curves[$curve_name,Gy]}"
    N="${elliptic_curves[$curve_name,N]}"
    H="${elliptic_curves[$curve_name,H]}"
    
    # Executa a geração da chave pública usando ECDH e armazena o resultado em R.
    R=$(./ecutils -ecdh -ecdh-ec-get "$curve_name" -ecdh-private-key F -ecdh-get-public-key)

    # Executa a definição da curva e a geração da chave pública usando ECDH e armazena o resultado em S.
    S=$(./ecutils -ecdh -ecdh-ec-define -ecdh-ec-define-p "$P" -ecdh-ec-define-a "$A" -ecdh-ec-define-b "$B" -ecdh-ec-define-gx "$Gx" -ecdh-ec-define-gy "$Gy" -ecdh-ec-define-n "$N" -ecdh-ec-define-h "$H" -ecdh-private-key F -ecdh-get-public-key)

    # Compara os resultados R e S obtidos acima e verifica se eles são iguais.
    if [ "$R" != "$S" ]; then
        echo "  >  ECDH Erro: $R != $S"
        exit 1
    fi
    
    # Executa a geração de outra chave pública usando ECDH, com uma chave privada (B).
    B2=$(./ecutils -ecdh -ecdh-ec-get "$curve_name" -ecdh-private-key B -ecdh-get-public-key)
    BPx=$(echo "$B2" | cut -d' ' -f1)
    BPy=$(echo "$B2" | cut -d' ' -f2)
    
    # Executa a geração de chave pública para outra entidade (F) usando ECDH.
    F=$(./ecutils -ecdh -ecdh-ec-get "$curve_name" -ecdh-private-key F -ecdh-get-public-key)
    FPx=$(echo "$F" | cut -d' ' -f1)
    FPy=$(echo "$F" | cut -d' ' -f2)
    
    # Executa a operação de compartilhamento de chave ECDH usando as chaves privadas e públicas de B e F, armazenando o resultado em U.
    U=$(./ecutils -ecdh -ecdh-ec-get "$curve_name" -ecdh-private-key B -ecdh-toshare -ecdh-toshare-public-key-px "$FPx" -ecdh-toshare-public-key-py "$FPy")

    # Executa a operação de definição de curva e compartilhamento de chave ECDH usando as chaves privadas e públicas de B e F, armazenando o resultado em V.
    V=$(./ecutils -ecdh -ecdh-ec-define -ecdh-ec-define-p "$P" -ecdh-ec-define-a "$A" -ecdh-ec-define-b "$B" -ecdh-ec-define-gx "$Gx" -ecdh-ec-define-gy "$Gy" -ecdh-ec-define-n "$N" -ecdh-ec-define-h "$H" -ecdh-private-key F -ecdh-toshare -ecdh-toshare-public-key-px "$BPx" -ecdh-toshare-public-key-py "$BPy")

    # Compara os resultados U e V obtidos acima e verifica se eles são iguais.
    if [ "$U" != "$V" ]; then
        echo "  >  ECDH Erro: $U != $V"
        exit 1
    fi
done

# Obtém o tempo de término da execução do loop.
end_time=$(date +%s%N)

# Calcula o tempo total de execução do loop e exibe-o.
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Concluído, tempo de execução: ${execution_time} ms"
```

### Testando ECDSA

```bash
# Exibe uma mensagem informativa indicando que os testes ECDSA estão sendo executados.
echo "  >  Testando ECDSA: ..."

# Obtém o tempo de início da execução do loop.
start_time=$(date +%s%N)

# Loop que itera sobre as curvas elípticas definidas.
for curve in "${curve_names[@]}"; do
    # Extrai o nome da curva (por exemplo, "secp192k1") da variável curve.
    curve_name="${curve%,*}"

    # Obtém os parâmetros da curva elíptica a partir do array elliptic_curves.
    P="${elliptic_curves[$curve_name,P]}"
    A="${elliptic_curves[$curve_name,A]}"
    B="${elliptic_curves[$curve_name,B]}"
    Gx="${elliptic_curves[$curve_name,Gx]}"
    Gy="${elliptic_curves[$curve_name,Gy]}"
    N="${elliptic_curves[$curve_name,N]}"
    H="${elliptic_curves[$curve_name,H]}"
    
    # Executa a geração da chave pública usando ECDSA e armazena o resultado em R.
    R=$(./ecutils -ecdsa -ecdsa-ec-get "$curve_name" -ecdsa-private-key F -ecdsa-get-public-key)

    # Executa a definição da curva e a geração da chave pública usando ECDSA e armazena o resultado em S.
    S=$(./ecutils -ecdsa -ecdsa-ec-define -ecdsa-ec-define-p "$P" -ecdsa-ec-define-a "$A" -ecdsa-ec-define-b "$B" -ecdsa-ec-define-gx "$Gx" -ecdsa-ec-define-gy "$Gy" -ecdsa-ec-define-n "$N" -ecdsa-ec-define-h "$H" -ecdsa-private-key F -ecdsa-get-public-key)

    # Compara os resultados R e S obtidos acima e verifica se eles são iguais.
    if [ "$R" != "$S" ]; then
        echo "  >  ECDSA Erro: $R != $S"
        exit 1
    fi
    
    # Extrai as coordenadas X e Y da chave pública R.
    RPx=$(echo "$R" | cut -d' ' -f1)
    RPy=$(echo "$R" | cut -d' ' -f2)
    
    # Define uma mensagem a ser assinada com ECDSA.
    message="2F4811D9EC890E12785B32A8D8FB037A180D1A479E3E0D33"
    
    # Executa a operação de assinatura ECDSA usando a chave privada F e a mensagem definida, armazenando o resultado em U.
    U=$(./ecutils -ecdsa -ecdsa-ec-define -ecdsa-ec-define-p "$P" -ecdsa-ec-define-a "$A" -ecdsa-ec-define-b "$B" -ecdsa-ec-define-gx "$Gx" -ecdsa-ec-define-gy "$Gy" -ecdsa-ec-define-n "$N" -ecdsa-ec-define-h "$H" -ecdsa-private-key F -ecdsa-signature -ecdsa-signature-message "$message")

    # Extrai as componentes "r" e "s" da assinatura U.
    UR=$(echo "$U" | cut -d' ' -f1)
    US=$(echo "$U" | cut -d' ' -f2)
    
    # Executa a operação de verificação da assinatura ECDSA usando a chave pública R e a assinatura U, armazenando o resultado em V.
    V=$(./ecutils -ecdsa -ecdsa-ec-get "$curve_name" -ecdsa-verify-signature -ecdsa-verify-signature-public-key-px "$RPx" -ecdsa-verify-signature-public-key-py "$RPy" -ecdsa-verify-signature-r "$UR" -ecdsa-verify-signature-s "$US" -ecdsa-verify-signature-signed-message "$message")
    
    # Verifica se o resultado da verificação da assinatura é igual a "1", indicando que a assinatura é válida.
    if [ "$V" != "1" ]; then
        echo "ECDSA Erro"
        exit 1
    fi
done

# Obtém o tempo de término da execução do loop.
end_time=$(date +%s%N)

# Calcula o tempo total de execução do loop e exibe-o.
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Concluído, tempo de execução: ${execution_time} ms"
```

### Testando ECK

```bash
# Exibe uma mensagem informativa indicando que os testes ECK estão sendo executados.
echo "  >  Testando ECK: ..."

# Define as curvas elípticas a serem testadas.
curve_names=("secp384r1" "secp521r1")

# Obtém o tempo de início da execução do loop.
start_time=$(date +%s%N)

# Loop que itera sobre as curvas elípticas definidas.
for curve in "${curve_names[@]}"; do
    # Extrai o nome da curva (por exemplo, "secp192k1") da variável curve.
    curve_name="${curve%,*}"

    # Obtém os parâmetros da curva elíptica a partir do array elliptic_curves.
    P="${elliptic_curves[$curve_name,P]}"
    A="${elliptic_curves[$curve_name,A]}"
    B="${elliptic_curves[$curve_name,B]}"
    Gx="${elliptic_curves[$curve_name,Gx]}"
    Gy="${elliptic_curves[$curve_name,Gy]}"
    N="${elliptic_curves[$curve_name,N]}"
    H="${elliptic_curves[$curve_name,H]}"
    
    # Gera uma mensagem aleatória.
    message=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 23 | head -n 1)
    
    # Executa a definição da curva elíptica e a codificação da mensagem usando ECK.
    R=$(./ecutils -eck -eck-ec-define -eck-ec-define-p "$P" -eck-ec-define-a "$A" -eck-ec-define-b "$B" -eck-ec-define-gx "$Gx" -eck-ec-define-gy "$Gy" -eck-ec-define-n "$N" -eck-ec-define-h "$H" -eck-encode -eck-encode-message "$message")
 
    # Extrai as coordenadas X, Y e J da codificação R.
    Px=$(echo "$R" | cut -d' ' -f1)
    Py=$(echo "$R" | cut -d' ' -f2)
    J=$(echo "$R" | cut -d' ' -f3)
    
    # Executa a operação de decodificação da mensagem usando as coordenadas Px, Py e J, obtendo a mensagem S.
    S=$(./ecutils -eck -eck-ec-get "$curve_name" -eck-decode -eck-decode-px "$Px" -eck-decode-py "$Py" -eck-decode-j "$J")
  
    # Compara a mensagem original com a mensagem decodificada e verifica se elas são iguais.
    if [ "$message" != "$S" ]; then
        echo "  >  ECK Erro: $message != $S"
        exit 1
    fi
    
done

# Obtém o tempo de término da execução do loop.
end_time=$(date +%s%N)

# Calcula o tempo total de execução do loop e exibe-o.
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Concluído, tempo de execução: ${execution_time} ms"
```

### Testando ECMO

```bash
# Exibe uma mensagem informativa indicando que os testes ECMO estão sendo executados.
echo "  >  Testing ECMO ASCII: ..."
curve_names=("secp192k1" "secp192r1" "secp256k1" "secp256r1" "secp384r1" "secp521r1")
start_time=$(date +%s%N)
for curve in "${curve_names[@]}"; do
    
    curve_name="${curve%,*}"
    
    P="${elliptic_curves[$curve_name,P]}"
    A="${elliptic_curves[$curve_name,A]}"
    B="${elliptic_curves[$curve_name,B]}"
    Gx="${elliptic_curves[$curve_name,Gx]}"
    Gy="${elliptic_curves[$curve_name,Gy]}"
    N="${elliptic_curves[$curve_name,N]}"
    H="${elliptic_curves[$curve_name,H]}"
    
    R=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key F -ecmo-get-public-key)
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key F -ecmo-get-public-key"
    
    S=$(./ecutils -ecmo -ecmo-ec-define -ecmo-ec-define-p "$P" -ecmo-ec-define-a "$A" -ecmo-ec-define-b "$B" -ecmo-ec-define-gx "$Gx" -ecmo-ec-define-gy "$Gy" -ecmo-ec-define-n "$N" -ecmo-ec-define-h "$H" -ecmo-private-key F -ecmo-get-public-key)
    echo "  >  ./ecutils -ecmo -ecmo-ec-define -ecmo-ec-define-p "$P" -ecmo-ec-define-a "$A" -ecmo-ec-define-b "$B" -ecmo-ec-define-gx "$Gx" -ecmo-ec-define-gy "$Gy" -ecmo-ec-define-n "$N" -ecmo-ec-define-h "$H" -ecmo-private-key F -ecmo-get-public-key"
    
    if [ "$R" != "$S" ]; then
        echo "  >  ECMO GetPublicKey Error: $R != $S"
        exit 1
    fi
    
    message=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 23 | head -n 1)
    
    E=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-eck-encoding-type "ascii" -ecmo-encrypt -ecmo-encrypt-message "$message")
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-eck-encoding-type "ascii" -ecmo-encrypt -ecmo-encrypt-message "$message""
    
    EPx=$(echo "$E" | cut -d' ' -f1)
    EPy=$(echo "$E" | cut -d' ' -f2)
    EJ=$(echo "$E" | cut -d' ' -f3)
    ER=$(echo "$E" | cut -d' ' -f4)
    ES=$(echo "$E" | cut -d' ' -f5)
    
    ALI=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-get-public-key)
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-get-public-key"
    
    ALIPx=$(echo "$ALI" | cut -d' ' -f1)
    ALIPy=$(echo "$ALI" | cut -d' ' -f2)

    E=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-eck-encoding-type "ascii" -ecmo-encrypt2 -ecmo-encrypt-px "$EPx" -ecmo-encrypt-py "$EPy" -ecmo-encrypt-j "$EJ" -ecmo-encrypt-r "$ER" -ecmo-encrypt-s "$ES" -ecmo-encrypt-toshare-public-key-px "$ALIPx" -ecmo-encrypt-toshare-public-key-py "$ALIPy")
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-eck-encoding-type "ascii" -ecmo-encrypt2 -ecmo-encrypt-px "$EPx" -ecmo-encrypt-py "$EPy" -ecmo-encrypt-j "$EJ" -ecmo-encrypt-r "$ER" -ecmo-encrypt-s "$ES" -ecmo-encrypt-toshare-public-key-px "$ALIPx" -ecmo-encrypt-toshare-public-key-py "$ALIPy""
    
    EPx=$(echo "$E" | cut -d' ' -f1)
    EPy=$(echo "$E" | cut -d' ' -f2)
    EJ=$(echo "$E" | cut -d' ' -f3)
    ER=$(echo "$E" | cut -d' ' -f4)
    ES=$(echo "$E" | cut -d' ' -f5)
    
    BOB=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-get-public-key)
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-get-public-key"
    
    BOBPx=$(echo "$BOB" | cut -d' ' -f1)
    BOBPy=$(echo "$BOB" | cut -d' ' -f2)

    E=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-eck-encoding-type "ascii" -ecmo-decrypt -ecmo-decrypt-px "$EPx" -ecmo-decrypt-py "$EPy" -ecmo-decrypt-j "$EJ" -ecmo-decrypt-r "$ER" -ecmo-decrypt-s "$ES" -ecmo-decrypt-toshare-public-key-px "$BOBPx" -ecmo-decrypt-toshare-public-key-py "$BOBPy")
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-eck-encoding-type "ascii" -ecmo-decrypt -ecmo-decrypt-px "$EPx" -ecmo-decrypt-py "$EPy" -ecmo-decrypt-j "$EJ" -ecmo-decrypt-r "$ER" -ecmo-decrypt-s "$ES" -ecmo-decrypt-toshare-public-key-px "$BOBPx" -ecmo-decrypt-toshare-public-key-py "$BOBPy""

    EPx=$(echo "$E" | cut -d' ' -f1)
    EPy=$(echo "$E" | cut -d' ' -f2)
    EJ=$(echo "$E" | cut -d' ' -f3)
    ER=$(echo "$E" | cut -d' ' -f4)
    ES=$(echo "$E" | cut -d' ' -f5)

    D=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-eck-encoding-type "ascii" -ecmo-decrypt2 -ecmo-decrypt-px "$EPx" -ecmo-decrypt-py "$EPy" -ecmo-decrypt-j "$EJ" -ecmo-decrypt-r "$ER" -ecmo-decrypt-s "$ES" -ecmo-decrypt-toshare-public-key-px "$ALIPx" -ecmo-decrypt-toshare-public-key-py "$ALIPy")
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-eck-encoding-type "ascii" -ecmo-decrypt2 -ecmo-decrypt-px "$EPx" -ecmo-decrypt-py "$EPy" -ecmo-decrypt-j "$EJ" -ecmo-decrypt-r "$ER" -ecmo-decrypt-s "$ES" -ecmo-decrypt-toshare-public-key-px "$ALIPx" -ecmo-decrypt-toshare-public-key-py "$ALIPy""

    if [ "$message" != "$D" ]; then
        echo "  >  ECMO Error: $message != $D"
        exit 1
    fi
    
done
end_time=$(date +%s%N)
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Finished, execution time: ${execution_time} ms"
```

## Conclusão
O *ecutils* é uma ferramenta versátil e poderosa para operações de criptografia baseadas em Curvas Elípticas. Com recursos que incluem a geração de curvas, operações de ponto e suporte a protocolos de segurança, ele se destaca como uma escolha valiosa para profissionais de segurança cibernética e desenvolvedores de software que precisam de criptografia avançada e segura. Com o *ecutils*, é possível realizar operações complexas enquanto mantém a segurança e a privacidade dos dados em mente. Sua flexibilidade e variedade de comandos tornam-no uma ferramenta essencial para lidar com desafios de criptografia em várias aplicações.
