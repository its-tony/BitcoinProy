import java.nio.file.Files;
import java.nio.file.Path;

/**
 * El programa funciona como una implementación de un intérprete de Bitcoin Script basado en una pila.
 * El sistema evalúa scripts de bloqueo y desbloqueo (P2PKH) procesando tokens de izquierda a derecha, utilizando una pila para el almacenamiento de operandos.
 * Utiliza {@link java.util.ArrayDeque} para garantizar operaciones de pila en complejidad O(1).
 * @author Diego Ayala, Antony Portillo, Alejandro Rustrian
 * @version 1.0
 */

public class Main {

    public static void main(String[] args) {
        try {

            //Permite que el usuario pueda usar usar un archivo por consola, de lo contrario se usará Data.txt por default
            String fileName = args.length > 0 ? args[0] : "Data.txt";
            boolean trace = args.length > 1 && args[1].equalsIgnoreCase("--trace");

            Path path = Path.of(fileName);

            if (!Files.exists(path)) {
                System.err.println("El archivo de script no existe: " + fileName);
                return;
            }

            String scriptRaw = Files.readString(path).trim();

            IOpcodeInterpreter interpreter = new Logica(trace);

            System.out.println("Se está evaluando script Bitcoin...\n");
            boolean result = interpreter.execute(scriptRaw);

            System.out.println("\n¿Transacción válida?: " + result);

        } catch (Exception e) {
            System.err.println("Hubo un error al ejecutar el script: " + e.getMessage());
        }
    }
}