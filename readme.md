# Informe de Equipo Automatizado

Este script en Python genera un informe detallado sobre la información de un equipo.

## Descripción

El script `Computer` recopila datos relevantes del sistema y crea un informe en formato Markdown con detalles sobre la CPU, la red, la información del disco y los puertos abiertos localmente.

## Funcionalidades

- **Recopilación de Datos:**
  - Nombre del equipo
  - Dirección IP
  - Nombre de usuario
  - Dominio del equipo
  - Información detallada de las conexiones de red
  - Detalles de los discos del sistema
  - Puertos abiertos localmente

- **Generación de Informe:**
  - Resumen de información clave
  - Informe completo con detalles más extensos

## Uso

El método `generar_informe()` crea un archivo markdown con el informe detallado del equipo.

## Instalación y Requisitos

El script está desarrollado en Python y requiere de ciertos módulos como `psutil`, `nmap`, `wmi`, `cpuinfo`, entre otros. Asegúrate de tenerlos instalados.

## Ejemplo

```python
computer = Computer()
computer.generar_informe()
```

# licencia
[MIT License](LICENSE)
