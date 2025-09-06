from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_INTEL
import logging
import sys

# Verificar argumentos
if len(sys.argv) != 2:
    print("Uso: python disasm_shellcode.py <archivo.bin>")
    sys.exit(1)

bin_file = sys.argv[1]

# Configurar logging
logging.basicConfig(filename='shellcode_disasm.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    with open(bin_file,'rb') as f:
        code = f.read()
except FileNotFoundError:
    print(f"Error: Archivo '{bin_file}' no encontrado.")
    sys.exit(1)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
md.syntax = CS_OPT_SYNTAX_INTEL  # Usar sintaxis Intel

print('Advanced Disassembly of shellcode with memory management insights:')
logging.info(f'Analizando archivo: {bin_file}')
logging.info('Starting advanced disassembly')
print('Address\tMnemonic\tOperands\t\tDetails')

# Diccionarios para análisis de flujo
jumps = []
calls = []
rets = []

for i in md.disasm(code, 0x0):
    details = ''
    if i.mnemonic.startswith('j'):  # Jump instructions
        jumps.append((i.address, i.mnemonic, i.op_str))
        details = 'Jump instruction'
    elif i.mnemonic == 'call':
        calls.append((i.address, i.mnemonic, i.op_str))
        details = 'Call instruction'
    elif i.mnemonic == 'ret':
        rets.append((i.address, i.mnemonic, i.op_str))
        details = 'Return instruction - potential ROP gadget'
    
    # Mostrar operandos detallados
    op_str = i.op_str
    if len(op_str) > 20:
        op_str = op_str[:17] + '...'
    print('0x%x:\t%s\t\t%s\t\t%s' % (i.address, i.mnemonic, op_str, details))

print('\nFlow Analysis:')
print(f'Total jumps: {len(jumps)}')
for addr, mn, op in jumps[:5]:  # Limitar output
    print(f'  Jump at 0x{addr:x}: {mn} {op}')

print(f'Total calls: {len(calls)}')
for addr, mn, op in calls[:5]:
    print(f'  Call at 0x{addr:x}: {mn} {op}')

print(f'Total returns: {len(rets)}')
for addr, mn, op in rets[:5]:
    print(f'  Ret at 0x{addr:x}: {mn} {op}')

# Print around interesting offsets with memory context
print('\nDetailed analysis around key offsets (simulating memory layout):')
for off in [0xB0, 0xBC, 0xC0, 0xC8, 0xCA]:
    start = max(0, off-16)
    end = min(len(code), off+16)
    print(f'\nBytes around 0x{off:X} (memory offset 0x{off:X}): {code[start:end].hex()}')
    print('Disassembly:')
    for i in md.disasm(code[start:end], start):
        print('  0x%x:\t%s\t%s' % (i.address, i.mnemonic, i.op_str))

# Análisis de gestión de memoria: detectar instrucciones relacionadas con memoria
print('\nMemory-related instructions:')
memory_ins = []
for i in md.disasm(code, 0x0):
    if i.mnemonic in ['mov', 'lea', 'push', 'pop', 'add', 'sub'] and ('rsp' in i.op_str or 'rbp' in i.op_str or '[' in i.op_str):
        memory_ins.append((i.address, i.mnemonic, i.op_str))
for addr, mn, op in memory_ins[:10]:  # Limitar
    print(f'  0x{addr:x}: {mn} {op}')

# Análisis avanzado de stack y prevención de violations
print('\nAdvanced Stack and Memory Safety Analysis:')
stack_pointer = 0  # Simular RSP
base_pointer = 0   # Simular RBP
potential_violations = []
stack_frames = []

for i in md.disasm(code, 0x0):
    if i.mnemonic == 'push':
        stack_pointer -= 8  # Asumir 64-bit
    elif i.mnemonic == 'pop':
        stack_pointer += 8
    elif i.mnemonic == 'sub' and 'rsp' in i.op_str:
        # Extraer valor substraído
        try:
            val = int(i.op_str.split(',')[1].strip(), 16) if '0x' in i.op_str else 0
            stack_pointer -= val
        except:
            pass
    elif i.mnemonic == 'add' and 'rsp' in i.op_str:
        try:
            val = int(i.op_str.split(',')[1].strip(), 16) if '0x' in i.op_str else 0
            stack_pointer += val
        except:
            pass
    elif i.mnemonic == 'mov' and 'rsp' in i.op_str and 'rbp' in i.op_str:
        base_pointer = stack_pointer  # Prolog típico
        stack_frames.append({'start': i.address, 'base': base_pointer})
    
    # Detectar accesos peligrosos
    if '[' in i.op_str:
        # Simular acceso a memoria
        if 'rsp' in i.op_str or 'rbp' in i.op_str:
            # Calcular offset
            try:
                offset_str = i.op_str.split('[')[1].split(']')[0]
                if '+' in offset_str:
                    offset = int(offset_str.split('+')[1].strip(), 16) if '0x' in offset_str else 0
                elif '-' in offset_str:
                    offset = -int(offset_str.split('-')[1].strip(), 16) if '0x' in offset_str else 0
                else:
                    offset = 0
                effective_addr = stack_pointer + offset if 'rsp' in i.op_str else base_pointer + offset
                if effective_addr < -0x1000 or effective_addr > 0x1000:  # Umbral para violation
                    potential_violations.append({'address': i.address, 'instruction': f'{i.mnemonic} {i.op_str}', 'effective_addr': effective_addr})
            except:
                pass

print(f'Simulated final stack pointer: {stack_pointer}')
print(f'Stack frames detected: {len(stack_frames)}')
for frame in stack_frames:
    print(f'  Frame at 0x{frame["start"]:x}, base: {frame["base"]}')

if potential_violations:
    print('Potential access violations detected:')
    for v in potential_violations:
        print(f'  0x{v["address"]:x}: {v["instruction"]} -> effective addr {v["effective_addr"]:x}')
else:
    print('No obvious access violations detected.')

# Detección de buffer overflows en desensamblado
print('\nBuffer Overflow Detection:')
buffer_risks = []
for i in md.disasm(code, 0x0):
    if i.mnemonic in ['rep', 'movsb', 'stosb'] and 'loop' in str(i.op_str).lower():
        buffer_risks.append({'address': i.address, 'instruction': f'{i.mnemonic} {i.op_str}'})
    elif i.mnemonic == 'call' and 'memcpy' in str(i.op_str).lower():  # Si hay llamadas a memcpy
        buffer_risks.append({'address': i.address, 'instruction': f'{i.mnemonic} {i.op_str}'})

for risk in buffer_risks:
    print(f'  Potential buffer overflow at 0x{risk["address"]:x}: {risk["instruction"]}')

# Análisis de compatibilidad para integración de técnicas avanzadas
print('\n=== ANÁLISIS DE COMPATIBILIDAD PARA INTEGRACIÓN ===')

# Evaluar compatibilidad general basada en el análisis
compatibility_score = 0
if len(memory_ins) < 20:  # Bajo uso de memoria indica estabilidad
    compatibility_score += 25
if not potential_violations:  # Sin violaciones de acceso
    compatibility_score += 30
if len(buffer_risks) == 0:  # Sin riesgos de buffer
    compatibility_score += 20
if len(jumps) < 15:  # Flujo de control manejable
    compatibility_score += 15
if len(calls) < 10:  # Pocas llamadas facilitan modificaciones
    compatibility_score += 10

print(f'Puntuación de compatibilidad para integración: {compatibility_score}/100')

# Análisis de integración para Tartarus Gate
print('\n=== GUÍA DE INTEGRACIÓN: TARTARUS GATE ===')
if compatibility_score > 60:
    print('✅ COMPATIBLE: El shellcode permite integración de Tartarus Gate')
    print('Cómo integrar:')
    print('  1. Identificar puntos de inserción (usar buffers seguros)')
    print('  2. Insertar código de resolución antes de SYSCALL')
    print('  3. Configurar RAX con hash de función')
    print('  4. Ejecutar resolución dinámica')
    print('Código de ejemplo disponible en analyze_shellcode.py')
else:
    print('⚠️ BAJA COMPATIBILIDAD: Revisar riesgos antes de integrar')

# Análisis de integración para DInvoke
print('\n=== GUÍA DE INTEGRACIÓN: DINVOKE ===')
if compatibility_score > 50:
    print('✅ COMPATIBLE: Posible reemplazar llamadas con DInvoke')
    print('Cómo integrar:')
    print('  1. Localizar CALL instructions')
    print('  2. Reemplazar con DInvoke::call')
    print('  3. Resolver direcciones dinámicamente')
    print('  4. Evitar tablas IAT')
else:
    print('⚠️ REQUIERE MODIFICACIONES: Stack o memoria inestables')

# Análisis de integración para Module Stomping
print('\n=== GUÍA DE INTEGRACIÓN: MODULE STOMPING ===')
if compatibility_score > 40:
    print('✅ COMPATIBLE: Estructuras permiten stomping')
    print('Cómo integrar:')
    print('  1. Identificar módulos objetivo')
    print('  2. Localizar sección .text')
    print('  3. Copiar shellcode modificado')
    print('  4. Ajustar referencias')
else:
    print('⚠️ ALTO RIESGO: Verificar estabilidad del módulo objetivo')

# Simulación de flujo para puntos de hijacking
print('\nThread Hijacking Flow Simulation:')
hijacking_points = []
for i in md.disasm(code, 0x0):
    if i.mnemonic in ['jmp', 'call'] and 'rax' in i.op_str:  # Posible redirección de ejecución
        hijacking_points.append({'address': i.address, 'instruction': f'{i.mnemonic} {i.op_str}'})

for hp in hijacking_points[:5]:
    print(f'  Potential hijacking point at 0x{hp["address"]:x}: {hp["instruction"]}')

# Detección de gadgets ROP
print('\nPotential ROP gadgets (sequences ending with RET):')
for i in range(len(code)):
    if code[i] == 0xC3:  # RET
        # Buscar instrucciones previas para formar gadget
        gadget_start = max(0, i-20)
        gadget = code[gadget_start:i+1]
        if len(gadget) > 1:
            print(f'Gadget at 0x{gadget_start:x} - 0x{i:x}: {gadget.hex()}')
            # Desensamblar el gadget
            for g in md.disasm(gadget, gadget_start):
                print(f'    0x{g.address:x}: {g.mnemonic} {g.op_str}')
            print()

# Definir variables para el reporte JSON
syscall_instructions = []
thread_hijacking_ins = []
hells_gate_compat = len([i for i in md.disasm(code, 0x0) if i.mnemonic == 'syscall']) > 0
tartarus_suggestions = []
dinvoke_suggestions = []
stomping_suggestions = []

# Análisis para Tartarus Gate
for i in md.disasm(code, 0x0):
    if i.mnemonic == 'syscall':
        syscall_instructions.append({'address': i.address, 'instruction': f'{i.mnemonic} {i.op_str}'})
        tartarus_suggestions.append({
            'syscall_address': i.address,
            'patching_offset': i.address - 10,
            'suggestion': 'Insertar resolución dinámica de syscall antes de SYSCALL.',
            'code_example': 'push rcx\npush rdx\nmov rcx, gs:[0x60]\n; ... resolución EAT',
            'risk_assessment': 'Bajo riesgo si se inserta en buffer seguro',
            'compatibility': 'Compatible con syscalls directos'
        })

# Análisis para DInvoke
for call in calls:
    addr, mn, op = call
    if 'rax' in op:
        dinvoke_suggestions.append({
            'call_address': addr,
            'suggestion': 'Reemplazar CALL RAX con DInvoke para evitar IAT.',
            'code_example': 'Usar dinvoke::call para función específica.'
        })

# Análisis para Module Stomping
for i in range(len(code) - 2):
    if code[i:i+2] == b'\x4D\x5A':  # MZ header
        stomping_suggestions.append({
            'mz_offset': i,
            'suggestion': 'Usar este offset para stomping, reemplazar sección .text con shellcode.',
            'code_example': f'Copiar shellcode a módulo objetivo en offset 0x{i:x}.'
        })

import json

logging.info('Disassembly and analysis completed')

# Generar reporte JSON
disasm_report = {
    'bin_file': bin_file,
    'shellcode_size': len(code),
    'jumps': jumps,
    'calls': calls,
    'rets': rets,
    'memory_instructions': memory_ins,
    'stack_analysis': {
        'final_stack_pointer': stack_pointer,
        'stack_frames': stack_frames,
        'potential_violations': potential_violations
    },
    'buffer_risks': buffer_risks,
    'syscall_instructions': syscall_instructions,
    'thread_hijacking_ins': thread_hijacking_ins,
    'hells_gate_compat': hells_gate_compat,
    'hijacking_points': hijacking_points,
    'advanced_integration': {
        'tartarus_gate': tartarus_suggestions,
        'dinvoke': dinvoke_suggestions,
        'module_stomping': stomping_suggestions
    }
}

with open('shellcode_disasm.json', 'w') as f:
    json.dump(disasm_report, f, indent=4)

print('\nDisassembly report saved to shellcode_disasm.json')
