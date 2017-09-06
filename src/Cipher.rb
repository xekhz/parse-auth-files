require 'openssl'
require 'digest/sha1'

class Cipher

@cipher 
@password
@key
#initializa o objecto 
# sempre q for criado um objecto de cifra solicita uma chave(password)
  def initialize()
    # create the cipher for encrypting
    ask_for_password
    end


    # Recebe uma string e devolve cifrada
    # Utiliza para gerar a cifra o aes-256-cbc e cifra com o a chave solicitada na criacao do pbjecto
    # 
    def cipher(message)
      @cipher = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
      @cipher.encrypt
      @key = Digest::SHA1.hexdigest("#{@password}")
      @cipher.key = @key
      encrypted = @cipher.update(message)
      encrypted << @cipher.final
      return encrypted
    end

    # recebe uma mensagem cifrada e decifra
    #
    #
    def decipher(enc_message)
      @cipher = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
      @cipher.decrypt
      @key = Digest::SHA1.hexdigest("#{@password}")
      @cipher.key = @key
      decrypted = @cipher.update(enc_message) + @cipher.final
      #decrypted << @cipher.final
      return decrypted
    end
    
    # Solicita a password para poder de/cifrar os dados
    #
    #
    def ask_for_password
      printf "\nPassword to cipher / decipher: "
      @password = gets
      #@key = Digest::SHA1.hexdigest("#{@password}")       
    end
    private :ask_for_password
end


# EXEMPLO DE UTILIZACAO
#
#c = Cipher.new
#p c.cipher("teste")
#p c.decipher(c.cipher("teste"))

