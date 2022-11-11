class Cliente:
    def __init__(self, indentificador, endereço):
        self.indentificador = indentificador
        self.endereço = endereço
        self.chave_secreta = None
        self.rsa_chave_secreta = None
