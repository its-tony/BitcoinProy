

## Como usar este README

Todos los comandos de este documento asumen que ya entraste a la carpeta `BitcoinProy` del repositorio :D

## Entrar a la carpeta del proyecto

Si estas en la raiz del repositorio:

```powershell
cd BitcoinProy
```

En macOS o Linux:

```bash
cd BitcoinProy
```

## Estructura principal

- `Main.java`: punto de entrada del programa. Lee un archivo de script y lo ejecuta con el interprete.
- `Logica.java`: implementacion principal del interprete.
- `Stack.java`: pila usada por el interprete.
- `IOpcodeInterpreter.java`: contrato del interprete.
- `InterpreterException.java`: excepcion interna para errores de ejecucion.
- `InterpreterTest.java`: suite de pruebas activa del proyecto.
- `PruebaP2PKH.java`: runner manual con varios casos de prueba conectados al interprete.
- `Data.txt`: documento de referencia sobre P2PKH. No es un script valido listo para ejecutar.
- `lib/junit-platform-console-standalone-6.0.0.jar`: libreria incluida para correr pruebas JUnit.

## Requisitos

- Tener instalado Java JDK 17 o superior.
- Tener disponibles los comandos `java` y `javac` en la terminal.
- Ejecutar los comandos desde la carpeta `BitcoinProy`.

## Como compilar

Compila los archivos principales y las pruebas activas:

```powershell
javac -cp "lib\junit-platform-console-standalone-6.0.0.jar;." Main.java Logica.java Stack.java IOpcodeInterpreter.java InterpreterException.java InterpreterTest.java PruebaP2PKH.java
```

En macOS o Linux:

```bash
javac -cp "lib/junit-platform-console-standalone-6.0.0.jar:." Main.java Logica.java Stack.java IOpcodeInterpreter.java InterpreterException.java InterpreterTest.java PruebaP2PKH.java
```

## Como correr las pruebas unitarias

La suite de pruebas que corresponde al estado actual del proyecto es `InterpreterTest.java`.

Ejecuta:

```powershell
java -jar "lib\junit-platform-console-standalone-6.0.0.jar" execute --class-path "." --select-class InterpreterTest
```

En macOS o Linux:

```bash
java -jar "lib/junit-platform-console-standalone-6.0.0.jar" execute --class-path "." --select-class InterpreterTest
```

Resultado esperado:

- JUnit encuentra `11 tests`
- Todos deben salir en verde

## Como correr la prueba manual de P2PKH

Esta clase ejecuta varios casos conectados al interprete actual:

```powershell
java PruebaP2PKH
```

Si quieres ver el rastreo token por token:

```powershell
java PruebaP2PKH --trace
```

## Como ejecutar el programa principal

El programa principal lee un archivo con el script:

```powershell
java Main nombre_del_archivo.txt
```

Ejemplo:

```powershell
java Main mi_script.txt
```

En macOS o Linux:

```bash
java Main mi_script.txt
```

Tambien puedes activar trazas:

```powershell
java Main mi_script.txt --trace
```

## Importante sobre `Data.txt`

`Data.txt` no contiene un script ejecutable puro. Contiene explicacion y ejemplos de P2PKH, por eso si corres:

```powershell
java Main
```

el resultado actual sera `false`.

Si quieres probar `Main.java`, crea un archivo con un script valido, por ejemplo:

```text
SIG_PUBKEY1 PUBKEY1 OP_DUP OP_HASH160 HASH_PUBKEY1 OP_EQUALVERIFY OP_CHECKSIG
```

y luego ejecuta:

```powershell
java Main mi_script.txt
```

## Archivo que no debes usar para las pruebas actuales

Existe un archivo llamado `Pruebas.java`, pero corresponde a una version anterior del proyecto basada en otra aproximacion. No es la suite activa y no debe usarse como referencia para correr las pruebas actuales.

Usa `InterpreterTest.java`.

## Flujo rapido

Si alguien clona el repositorio, el flujo minimo es este:

```powershell
cd BitcoinProy
javac -cp "lib\junit-platform-console-standalone-6.0.0.jar;." Main.java Logica.java Stack.java IOpcodeInterpreter.java InterpreterException.java InterpreterTest.java PruebaP2PKH.java
java -jar "lib\junit-platform-console-standalone-6.0.0.jar" execute --class-path "." --select-class InterpreterTest
```
