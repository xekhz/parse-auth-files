class Debugger
# 1 - msg de informacao
# 2 - estrutras de variaveis
# 3 - tudo
# sem necessidade de metodos de instancia   
  @level=-1
  #
  # Class puramente auxiliar para controlar as mensagens de erro durante o desenvolvimento
  # genericamente
  # * 1 - msg de informacao
  # * 2 - estrutras de variaveis
  # * 3 - tudo
  # 
def initialize
end

def self.debug(msg,l)
  if( l <= @level ) then
    printf msg.to_s 
  end
end

def self.set_level(l)
@level = l
end

def self.get_level
  p @level
end

end