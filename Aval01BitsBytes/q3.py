def read_jpeg_metadata(file_path):
    """Ler os metadados de uma imagem JPEG e retorna a altura e largura da imagem."""
    with open(file_path, 'rb') as file:
        # Ler os primeiros 6 bytes para verificar o cabeçalho JPEG.
        header = file.read(6)
        
        # Verifica se o arquivo é um JPEG.
        if header[0:2] != b'\xff\xd8':
            raise ValueError("O arquivo não é JPEG válido.")
        
        # Ler 4 bytes que são 'ignorados'.
        file.read(4)
        
        # Ler o tamanho dos metadados presente na image.
        app1_data_size = int.from_bytes(file.read(2), 'big')
        
        #Ler os metadados.
        app1_data = file.read(app1_data_size)
        
        #Ler a quantidade de metadados na posição 16
        num_metadata = int.from_bytes(app1_data[16:18], 'big')
        
        # Inicializa variaveis para altura e largura.
        height = None
        width = None
        
        # A partir da posição 18 ler os metadados.
        position = 18
        while position < app1_data_size:
            # Ler o tipo de metadado '2 bytes'
            metadata_type = int.from_bytes(app1_data[position:position + 2], 'big')
            position += 2
            
            # Ler o tipo do metadado '2 bytes'
            data_type = int.from_bytes(app1_data[position:position + 2], 'big')
            position += 2
            
            # Ler o numero de repetições '4 bytes'
            repetitions = int.from_bytes(app1_data[position:position + 4], 'big')
            position += 4
            
            #LEr o valor do metadado '4 bytes ou offset'
            value = int.from_bytes(app1_data[position:position + 4], 'big')
            position += 4
            
            # Verifica se o metadado é altura ou largura
            if metadata_type == 0x0101:  # Altura
                height = value
            elif metadata_type == 0x0100:  # Largura
                width = value
            
            # Se ambos os valores forem encontrados sai do loop
            if height is not None and width is not None:
                break
        
        return height, width

 
file_path = 'C:\Users\Serginho\Downloads\IMG_20250509_184205.jpg'  # Substitua pelo caminho do seu arquivo JPEG
try:
    height, width = read_jpeg_metadata(file_path)
    print(f"Altura da imagem: {height} pixels")
    print(f"Largura da imagem: {width} pixels")
except Exception as e:
    print(f"Erro: {e}")
