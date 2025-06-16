import sys
import subprocess
import platform
import re

def parse_gps_coordinate(coord_str):
    """
    Converte coordenada GPS do formato '25 deg 15' 30.12" N' pra decimal
    """
    # coord_str: 25 deg 15' 30.12" N
    regex = r"(\d+)\s+deg\s+(\d+)'[\s]?([\d\.]+)\"?\s*([NSEW])"
    match = re.match(regex, coord_str.strip())
    if not match:
        return None
    degrees = float(match.group(1))
    minutes = float(match.group(2))
    seconds = float(match.group(3))
    direction = match.group(4)
    decimal = degrees + minutes/60 + seconds/3600
    if direction in ['S', 'W']:
        decimal = -decimal
    return decimal

def get_gps_via_exiftool(filepath):
    """
    Usa exiftool para ter a latitude e longitude da foto
    Retorna (lat, lon) ou None se não encontrar.
    """
    try:
        result = subprocess.run(
            ['exiftool', filepath],
            capture_output=True,
            text=True,
            check=True
        )
        lat = None
        lon = None
        # Buscar linhas de GPSLatitude e GPSLongitude
        for line in result.stdout.splitlines():
            if 'GPS Latitude' in line:
                # GPS Latitude                    : 25 deg 15' 30.12" N
                parts = line.split(':', 1)
                if len(parts) == 2:
                    lat = parse_gps_coordinate(parts[1].strip())
            elif 'GPS Longitude' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    lon = parse_gps_coordinate(parts[1].strip())
        if lat is not None and lon is not None:
            return lat, lon
        else:
            return None
    except subprocess.CalledProcessError:
        return None
    except FileNotFoundError:
        print("Erro: 'exiftool' não encontrado. Instale o exiftool para usar este programa.")
        sys.exit(1)

def open_map(lat, lon):
    """
    Abre o navegador com o OpenStreetMap no ponto definido.
    """
    url = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"
    system = platform.system()
    try:
        if system == 'Windows':
            subprocess.run(['start', url], shell=True, check=True)
        elif system == 'Darwin':  # macOS
            subprocess.run(['open', url], check=True)
        else:  # Linux e outros
            subprocess.run(['xdg-open', url], check=True)
    except Exception as e:
        print(f"Erro ao abrir o navegador: {e}")

def main():
    """
    Função principal que processa, estrai localização e abre mapa.
    """
    if len(sys.argv) != 2:
        print("Uso: python show_photo_location.py <caminho_da_imagem.jpg>")
        sys.exit(1)

    filepath = sys.argv[1]
    gps = get_gps_via_exiftool(filepath)
    if gps:
        lat, lon = gps
        print(f"Localização encontrada: Latitude {lat:.6f}, Longitude {lon:.6f}")
        open_map(lat, lon)
    else:
        print("Erro: Não foi possível encontrar informações de geolocalização na foto.")

if __name__ == "__main__":
    main()

