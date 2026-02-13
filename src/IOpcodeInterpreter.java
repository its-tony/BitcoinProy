public interface IOpcodeInterpreter {

    /**
     * La interfaz ejecuta un script completo de Bitcoin Script.
     * @param script cadena con opcodes y datos separados por espacios
     * @return true si la ejecución termina válida
     */
    boolean execute(String script);

    /**
     * Se encarga de procesar un token individual del script.
     */
    void processToken(String token);

    /**
     * Se encarga de reiniciar el estado del intérprete (pila, flags, etc).
     */
    void reset();
}