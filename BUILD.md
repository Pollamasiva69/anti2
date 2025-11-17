# Instrucciones de Compilación

## Dependencias Requeridas

### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    gcc \
    make \
    libpcap-dev \
    libjansson-dev \
    libpthread-stubs0-dev
```

### Dependencias Opcionales (Recomendadas)

```bash
# Para API REST
sudo apt-get install -y libmicrohttpd-dev

# Para GeoIP
sudo apt-get install -y libmaxminddb-dev

# Para eBPF/XDP
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r)
```

### Red Hat/CentOS/Fedora

```bash
sudo yum install -y \
    gcc \
    make \
    libpcap-devel \
    jansson-devel
```

## Compilación

### Compilación Normal (Producción)

```bash
cd /home/user/anti2
make clean
make -j4
```

El binario se generará en: `bin/ddos-protect`

### Compilación Debug

```bash
make clean
make DEBUG=1
```

Esto compila con símbolos de debug y sanitizers (AddressSanitizer, UndefinedBehaviorSanitizer).

### Compilación con Profiling

```bash
make clean
make profile
```

### Verificar la Compilación

```bash
# Ver el binario
ls -lh bin/ddos-protect

# Ver información del binario
file bin/ddos-protect

# Ver dependencias
ldd bin/ddos-protect
```

## Programa eBPF/XDP

Para compilar el programa XDP (requiere clang):

```bash
make ebpf
```

El objeto eBPF se generará en: `ebpf/xdp_filter.o`

## Solución de Problemas

### Error: "jansson.h: No such file or directory"

```bash
sudo apt-get install libjansson-dev
```

### Error: "pcap.h: No such file or directory"

```bash
sudo apt-get install libpcap-dev
```

### Error: "microhttpd.h: No such file or directory"

Esto es opcional. Puedes:
1. Instalar: `sudo apt-get install libmicrohttpd-dev`
2. O deshabilitar la API en el código

### Warnings sobre optimizaciones

Los warnings sobre optimizaciones específicas de CPU son normales y pueden ignorarse.

### Error de permisos

Si obtienes errores de permisos, asegúrate de ejecutar con privilegios adecuados.

## Instalación

Una vez compilado exitosamente:

```bash
sudo make install
```

Esto instalará:
- Binario en `/usr/local/bin/ddos-protect`
- Configuración en `/etc/ddos-protect/`
- Servicio systemd
- Dashboard web en `/usr/share/ddos-protect/web/`

## Verificación Post-Instalación

```bash
# Verificar instalación
which ddos-protect

# Verificar versión
ddos-protect --version

# Verificar configuración
ddos-protect --test /etc/ddos-protect/default.conf

# Iniciar servicio
sudo systemctl start ddos-protect

# Ver estado
sudo systemctl status ddos-protect

# Ver logs
sudo journalctl -u ddos-protect -f
```

## Modo de Prueba (Sin Root)

Para probar sin permisos root (funcionalidad limitada):

```bash
# Compilar
make

# Ejecutar en modo test
./bin/ddos-protect config/default.conf
```

**Nota**: El modo sin root no puede capturar paquetes reales ni aplicar reglas de firewall.

## Desinstalación

```bash
sudo make uninstall
```

## Limpieza

```bash
# Limpiar objetos compilados
make clean

# Limpiar todo incluyendo configuración
make distclean
```

## Requisitos del Sistema

- **OS**: Linux (kernel 4.15+, recomendado 5.0+)
- **Arquitectura**: x86_64
- **RAM**: Mínimo 4GB
- **Compilador**: GCC 7+ o Clang 6+
- **Permisos**: Root para captura de paquetes

## Optimizaciones de Compilación

El Makefile incluye optimizaciones agresivas:

- `-O3`: Máxima optimización
- `-march=native`: Instrucciones específicas del CPU
- `-flto`: Link-time optimization
- `-funroll-loops`: Loop unrolling
- `-ftree-vectorize`: Auto-vectorización

Si tienes problemas, puedes compilar sin optimizaciones:

```bash
make CFLAGS="-O0 -g"
```

## Prueba Rápida

Después de compilar:

```bash
# Test básico (sin root, solo verifica que compile)
./bin/ddos-protect --help

# Test de configuración
./bin/ddos-protect --test config/default.conf

# Test con simulación (requiere root)
sudo ./bin/ddos-protect config/default.conf
```

## Soporte

Si tienes problemas de compilación:

1. Verifica que todas las dependencias estén instaladas
2. Revisa los logs de compilación
3. Intenta compilar en modo debug
4. Reporta el issue en GitHub con el log completo
