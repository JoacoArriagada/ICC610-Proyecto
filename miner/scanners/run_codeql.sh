#!/bin/bash
# Ejecutar CodeQL sin usar /opt/codeql-queries
export HOME=/home/cherry
# Crear directorio temporal para packs
mkdir -p /tmp/codeql-packs
# Descargar pack en directorio aislado
codeql pack download --additional-packs /tmp/codeql-packs codeql/javascript-queries 2>&1
# Ejecutar con search-path vacío
codeql database analyze "$1" codeql/javascript-queries --search-path=/tmp/codeql-packs -o "$2" 2>&1
