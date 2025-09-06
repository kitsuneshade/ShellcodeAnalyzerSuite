# 🔍 Suite de Análisis de Shellcode � Shellcode Analyzer Suite

## 🚀 Análisis Avanzado de She### Tartarus Gate
- Detecta puntos de syscall y sugiere inserción de resolución dinámica.
- **Código completo incluido**: El script genera el código assembly completo para Tartarus Gate.
- Evalúa compatibilidad para syscalls directos sin detección.
- Incluye función de hash (djb2) para búsqueda de funciones.
- Offsets exactos para inserción sin romper el shellcode.

### DInvoke
- Identifica llamadas a funciones y propone reemplazos con DInvoke.
- Evita tablas de importación (IAT) para sigilo mejorado.

### Module Stomping
- Busca estructuras PE embebidas y offsets específicos para stomping.
- Sugiere reemplazo de secciones .text con shellcode modificado. Cargadores Rust Seguros

**¡Potencia tus cargadores basados en Rust con insights profundos del shellcode!** Previene violaciones de acceso, detecta patrones de syscall, simula comportamiento de pila y asegura integración perfecta con técnicas de Syscalls Directos y Thread Hijacking.

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Capstone](https://img.shields.io/badge/Capstone-5.0+-green.svg)](https://www.capstone-engine.org/)
[![Security](https://img.shields.io/badge/Security-First-red.svg)]()

---

## 📋 Qué Hace Esta Suite

Esta poderosa suite analiza binarios de shellcode (archivos `.bin`) para proporcionar insights comprehensivos para construir cargadores Rust robustos y resistentes a evasión. Se enfoca en **seguridad de memoria**, **detección de syscall** y **compatibilidad de integración** para evitar crashes y detección.

### 🎯 Características Clave

- **🛡️ Prevención de Violaciones de Acceso**: Simula acceso a pila y memoria para detectar crashes potenciales antes del despliegue.
- **🔍 Análisis de Syscall y Thread Hijacking**: Identifica syscalls directos, modificaciones de contexto y puntos de hijacking.
- **📊 Simulación de Pila**: Rastrea cambios en RSP/RBP, problemas de alineación y patrones de uso.
- **🧠 Detección de Entropía y Patrones**: Descubre ofuscación, datos embebidos y gadgets ROP.
- **📈 Recomendaciones de Integración Avanzada**: Evalúa compatibilidad con Hell’s Gate/Tartarus Gate, DInvoke y Module Stomping.
- **🔧 Análisis de Buffers Seguros**: Identifica áreas seguras para inyección de código adicional.
- **📝 Reportes Detallados JSON**: Genera reportes JSON completos para integración automática en cargadores Rust.

---

## 🛠️ Resumen de Scripts

### 1. `analyze_shellcode.py` - Motor de Análisis Comprehensivo
- **Propósito**: Análisis estático de shellcode para seguridad, gestión de memoria e integración.
- **Aspectos Destacados**:
  - Cálculo de entropía y detección de ofuscación.
  - Simulación avanzada de pila con Capstone.
  - Detección de buffer overflow y violaciones de acceso.
  - Evaluación de integración de syscall con Tartarus Gate.
  - Análisis de compatibilidad con DInvoke y Module Stomping.
  - Identificación de buffers seguros para modificaciones.
  - Generación de reporte JSON con recomendaciones específicas de integración.

### 2. `disasm_shellcode.py` - Desensamblado y Análisis de Flujo
- **Propósito**: Desensambla shellcode y analiza flujo de ejecución para técnicas avanzadas.
- **Aspectos Destacados**:
  - Desensamblado completo x64 usando Capstone.
  - Análisis de jump/call/return y flujo de control.
  - Detección de instrucciones relacionadas con memoria.
  - Identificación de gadgets ROP y puntos de hijacking.
  - Sugerencias específicas para integración con Tartarus Gate, DInvoke y Module Stomping.
  - Simulación de flujo de thread hijacking.
  - Reporte JSON con offsets exactos para modificaciones.

---

## 📦 Requisitos

- **Python 3.8+**
- **Capstone Engine** (`pip install capstone`)
- **Archivo binario de shellcode** (formato `.bin`)

---

## 🚀 Instalación

1. Clona o descarga los scripts a tu workspace.
2. Instala dependencias:
   ```bash
   pip install capstone
   ```
3. Asegúrate de que tu archivo de shellcode esté en formato `.bin`.

---

## 💻 Uso

### Analizar Shellcode
```bash
python analyze_shellcode.py <tu_shellcode.bin>
```

### Desensamblar y Analizar Flujo
```bash
python disasm_shellcode.py <tu_shellcode.bin>
```

**Ejemplo:**
```bash
python analyze_shellcode.py calc_shellcode.bin
```

---

## � Características Avanzadas de Integración

### Tartarus Gate
- Detecta puntos de syscall y sugiere inserción de resolución dinámica.
- Evalúa compatibilidad para syscalls directos sin detección.

### DInvoke
- Identifica llamadas a funciones y propone reemplazos con DInvoke.
- Evita tablas de importación (IAT) para sigilo mejorado.

### Module Stomping
- Busca estructuras PE embebidas y offsets para stomping.
- Sugiere reemplazo de secciones .text con shellcode modificado.

### Buffers Seguros
- Identifica áreas NOP y datos embebidos para inyección segura.
- Previene corrupciones al agregar código adicional.

---

## �📊 Salida de Ejemplo

### analyze_shellcode.py
```
Tamaño del shellcode: 276 bytes
Entropía: 5.9208 (baja - fácil de modificar)
Simulación Avanzada de Pila:
Uso de pila: 104 bytes
Problemas de alineación: 1 detectado (arreglar antes de integración)

Análisis de Tartarus Gate:
Puntos de syscall detectados: 0
Sugerencia de parche en 0x0: Insertar resolución dinámica de syscall.

Análisis de DInvoke:
Llamadas a funciones detectadas: 0

Análisis de Module Stomping:
Estructuras PE detectadas: 0

Integración de syscall posible: True
Recomendación: Baja entropía: Fácil integrar syscalls directos sin romper ofuscación.
```

### disasm_shellcode.py
```
Desensamblado Avanzado de shellcode con insights de gestión de memoria:
0x0: cld
0x1: and rsp, 0xffffffffff...
...
Análisis de Flujo:
Saltos totales: 9
Llamadas totales: 4
Análisis de Syscalls y Thread Hijacking:
Syscalls directos detectados: 0
Indicadores de thread hijacking: 5
Compatible con Hell’s Gate: False
```

---

## 📁 Archivos de Salida

- **`shellcode_analysis.json`**: Reporte JSON detallado con todos los datos de análisis.
- **`shellcode_analysis.log`**: Logging del proceso de análisis.
- **`shellcode_disasm.log`**: Logging de desensamblado.

¡Usa el JSON para integrar hallazgos en tu cargador Rust!

---

## 🔧 Características Avanzadas

### Seguridad de Memoria Primero
- **Chequeos de Alineación de Pila**: Asegura alineación de 16 bytes antes de llamadas (requisito x64).
- **Simulación de Violaciones**: Detecta accesos inválidos a memoria usando cálculos de offset.
- **Detección de Buffer Overflow**: Identifica operaciones riesgosas como REP MOVSB/STOSB.

### Integración de Syscall
- **Detección de Syscall Directo**: Encuentra patrones MOV RAX, syscall_num; SYSCALL.
- **Compatibilidad Hell’s Gate**: Evalúa potencial de shadowing.
- **Puntos de Thread Hijacking**: Localiza acceso a contexto y oportunidades de redirección.

### Personalización
- Extiende fácilmente detección de patrones para nuevos syscalls o técnicas.
- Modifica simulación de pila para arquitecturas personalizadas.

---

## 🤝 Contribuyendo

¿Encontraste un bug o quieres agregar una característica? ¡Abre un issue o PR!

1. Haz fork del repo.
2. Crea una rama de característica.
3. Prueba exhaustivamente (especialmente simulaciones de memoria).
4. Envía un PR con descripción detallada.

---

## ⚠️ Descargo de Responsabilidad

Esta herramienta es para propósitos educativos e investigativos en ciberseguridad. Úsala responsablemente y en cumplimiento con leyes. Los autores no son responsables de mal uso.

---

## 📄 Licencia

Licencia MIT - Libre para usar, modificar y distribuir.

---
