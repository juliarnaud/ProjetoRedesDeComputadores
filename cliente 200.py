from socket import socket, AF_INET, SOCK_STREAM
import random
import cryptocode
import rsa
from cryptography.fernet import Fernet


# função que comunica com o servidor sobre o indetificador
def AcharIndentificador(mClientSocket, indentificador="None"):
    existe_chave = True
    mClientSocket.send(indentificador.encode())  # envia o indentificador que possui ("None" para não possuir nenhum id)
    resp = mClientSocket.recv(2048)  # recebe a resposta do servidor sobre o status do indentificador
    resp = resp.decode()
    if resp != "ID OK":  # se o indentificador não existir ou não for encontrado é criado um novo indentificador e o cliente salva ele
        indentificador = mClientSocket.recv(2048)  # recebe o novo indentificador
        indentificador = indentificador.decode()
        existe_chave = False
    
    return existe_chave

def Handshake(mClientSocket, A_ChavePrivClient):
    
    mensagem = "CLIENT HELLO   "  # ta fazendo a primeira requisição pro servidor
    mClientSocket.send(mensagem.encode())  # Ta notificando pro servidor que esse é o client hello, ou seja, ta pedindo as chaves publicas

    while True:

        req = mClientSocket.recv(2048)
        req = req.decode()  # recebe a resposta do servidor, se tudo der certo tem que receber o server hello
        req = req[:15]

        if req == "SERVER HELLO   ":
            P_ChavePubServ = mClientSocket.recv(2048)  # recebendo as duas chaves publicas
            P_ChavePubServ = int(P_ChavePubServ.decode())

            G_ChavePubServ = mClientSocket.recv(2048)
            G_ChavePubServ = int(G_ChavePubServ.decode())  # decodificando para int

            # cipher é um numero pré criptografia que utliza as chaves publicas e privadas para fazer um segredo que vai ser compartilhado entre o cliente e servidor
            # vai ser usado como parametro para calcular a chave secreta
            # tambem é chamado de chave modular
            X_cipherCliente = int(pow(G_ChavePubServ, A_ChavePrivClient, P_ChavePubServ))

            # transformando para string para mandar para o servidor
            # a função encode só aceita string como parametro para codificar
            # por isso tou transformando em string antes de mandar
            X_cipherCliente = str(X_cipherCliente)

            mensagem = "CHANGE CIPHER  "  # cabeçalho para o servidor entender o que ta acontecendo (troca dos segredos compartilhados)
            mClientSocket.send(mensagem.encode())

            mClientSocket.send(X_cipherCliente.encode())  # mandando o cipher
            Y_cipherServidor = mClientSocket.recv(2048)  # recebendo o cipher
            Y_cipherServidor = int(Y_cipherServidor.decode())  # decodificando direto pra inteiro para poder calcular dps

        if req == "RSA CHANGE KEY ":  # faz a troca de chaves da biblioteca de assinatura digital
            resp = "RSA CHANGE KEY "
            mClientSocket.send(resp.encode())  # reponde, notificando para o servidor que irá ocorrera a troca de chaves

            (rsa_chave_pub_cliente, rsa_chave_priv_cliente) = rsa.newkeys(2048)

            rsa_chave_pub_cliente = rsa_chave_pub_cliente.save_pkcs1(format="DER")  # serializa a chave publica do cliente para bytes
            mClientSocket.send(rsa_chave_pub_cliente)  # envia a chave publica do cliente para o servidor

            
        if req == "HANDSHAKE FIN  ":
            chave_secreta_cliente = int(pow(Y_cipherServidor, A_ChavePrivClient, P_ChavePubServ))  # calculo da chave secreta

            mClientSocket.send(req.encode())  # alertanado para o servidor que ja possui a chave secreta

            return str(chave_secreta_cliente), rsa_chave_priv_cliente


# função que lida com as requisições get
def GET(mClientSocket, req, rsa_chave_priv_cliente, chave_secreta_cliente):


    # assinatura digital
    req = cryptocode.encrypt(req, chave_secreta_cliente)  # criptografia da requisição do get
    req = req.encode()  # transformando em bytes para mandar pro servidor
    mClientSocket.send(req)

    req_assinado = rsa.sign(req, rsa_chave_priv_cliente, 'SHA-512')  # assinatura digital
    mClientSocket.send(req_assinado)  # envio da assinatura digital para o servidor
    
    #troca de chave de criptografia de arquivo

    with open("filekey.key", "wb") as key_file:
        crypt_keybits = mClientSocket.recv(2048)
        crypt_key_decode = crypt_keybits.decode()
        crypt_key = cryptocode.decrypt(crypt_key_decode, chave_secreta_cliente)

        crypt_key = crypt_key.encode()
        key_file.write(crypt_key)

    with open('filekey.key', 'rb') as filekey:  # Lendo a chave recebida
        key = filekey.read()

    usable_key = Fernet(key)


    req = req.decode()
    req = cryptocode.decrypt(req, chave_secreta_cliente)

    # Recebe o cabeçalho

    cabecalho = mClientSocket.recv(2048)
    cabecalho = cabecalho.decode()
    cabecalho = cryptocode.decrypt(cabecalho, chave_secreta_cliente)
    print(cabecalho)

    # se cabeçalho não for 200, ou seja, não for ok, return. Fecha a função get caso não seja 200 OK
    if cabecalho[9:12] != "200": 
        return


    with open(req, "wb") as file:  # Inicio da criação do arquivo pedido
        # While permanecer enquanto ouver linhas para serem escritas
            # Recebimento das linhas do arquivo 1 milhão de bits pois as linhas são imprevisíveis
        data = mClientSocket.recv(1000000)
        # Escrita das linhas do arquivo na pasta do Cliente
        file.write(data)

    with open(req, "rb") as crip_file:
        crypted = crip_file.read()

    decrypt = usable_key.decrypt(crypted)

    with open(req, 'wb') as final_file:
        final_file.write(decrypt)

# DADOS

# essa é a chave privada do cliente
# a função randint escolher um numero aleatório. (1, 64) diz que esse numero vai ser entre 1 e 64
# eu so escolhi qualquer numero para ser o 64, podia ser qualquer um (acho)
A_ChavePrivClient = random.randint(1, 64)
chave_secreta_cliente = None

indentificador = "f37ddfeb-5550-11ed-a6bf-00e04c05b93a"

mClientSocket = socket(AF_INET, SOCK_STREAM)  # criando o socket
mClientSocket.connect(('127.0.0.1', 1236))  # se conectando com o servidor
print("Conexão iniciada...")

# a primeira comunicação é para ver se o cliente ja se comunicou com o servidor antes e ser indentificado no servidor
existe_chave = AcharIndentificador(mClientSocket, indentificador)

if not existe_chave:
    # é necessário fazer o primeiro contato com o servidor para garantir a criptografia
    # a função handshake é responsavel por calcular a chave de criptografia utilizada para a troca de mensagens
    chave_secreta_cliente, rsa_chave_priv_cliente = Handshake(mClientSocket, A_ChavePrivClient)



# requisição para código 200 OK
req = "teste.txt"
GET(mClientSocket, req, rsa_chave_priv_cliente, chave_secreta_cliente)