import java.util.ArrayDeque;
import java.util.Deque;
public class Logica implements IOpcodeInterpreter {

    private final Stack stack;
    private final boolean trace;
    private boolean failed;
    private String lastError;

    // condicionales
    private boolean ejecutando = true;
    private final Deque<Boolean> ifStack = new ArrayDeque<>();

    public Logica(boolean trace) {
        this.stack = new Stack();
        this.trace = trace;
        this.failed = false;
    }

    @Override
    public boolean execute(String script) {

        reset();

        if (script == null || script.trim().isEmpty()) {
            lastError = "El script está vacío.";
            return false;
        }

        String[] tokens = script.trim().split("\\s+");

        try {
            for (String token : tokens) {

                if (!ejecutando &&
                    !token.equals("OP_IF") &&
                    !token.equals("OP_ELSE") &&
                    !token.equals("OP_ENDIF")) {
                    continue;
                }

                processToken(token);

                if (failed) {
                    return false;
                }

                if (trace) {
                    System.out.println("Token: " + token);
                    System.out.println("Stack: " + stack);
                    System.out.println("------------------");
                }
            }

            if (!ifStack.isEmpty()) {
                throw new InterpreterException("Bloque condicional sin cerrar: falta OP_ENDIF.");
            }

            return !stack.isEmpty() && stack.pop().equals("1");
        } catch (InterpreterException e) {
            lastError = e.getMessage();

            if (trace) {
                System.out.println("Error: " + lastError);
                System.out.println("------------------");
            }

            return false;
        }
    }

    private boolean verificarFirma(String sig, String pubkey) {
        return sig.equals("SIG_" + pubkey);
    }

    private void requireStackSize(int expectedSize, String operation) {
        if (stack.size() < expectedSize) {
            throw new InterpreterException(
                "No hay suficientes elementos en la pila para " + operation + "."
            );
        }
    }

    private int parsePositiveInteger(String value, String operation) {
        try {
            int parsed = Integer.parseInt(value);
            if (parsed < 0) {
                throw new InterpreterException(
                    "Se encontró un entero negativo en " + operation + ": " + value
                );
            }
            return parsed;
        } catch (NumberFormatException e) {
            throw new InterpreterException(
                "Se esperaba un entero válido en " + operation + " pero se recibió: " + value
            );
        }
    }

    @Override
    public void processToken(String token) {

        switch (token) {

            case "OP_DUP" -> {
                requireStackSize(1, "OP_DUP");
                stack.push(stack.peek());
            }

            case "OP_DROP" -> {
                requireStackSize(1, "OP_DROP");
                stack.pop();
            }

            case "OP_HASH160" -> {
                requireStackSize(1, "OP_HASH160");
                String value = stack.pop();
                stack.push("HASH_" + value); 
            }

            case "OP_EQUAL" -> {
                requireStackSize(2, "OP_EQUAL");

                String b = stack.pop();
                String a = stack.pop();

                if (a.equals(b)) {
                    stack.push("1");
                } else {
                    stack.push("0");
                }
            }

            case "OP_EQUALVERIFY" -> {
                requireStackSize(2, "OP_EQUALVERIFY");

                String b = stack.pop();
                String a = stack.pop();

                if (!a.equals(b)) {
                    failed = true; // fallo inmediato
                }
            }

            case "OP_CHECKSIG" -> {
                requireStackSize(2, "OP_CHECKSIG");

                String pubkey = stack.pop();
                String sig = stack.pop();

                if (verificarFirma(sig, pubkey)) {
                    stack.push("1");
                    } else {
                    failed = true;
                }
            }

            // CONDICIONALES
            case "OP_IF" -> {
                requireStackSize(1, "OP_IF");

                String cond = stack.pop();
                boolean valor = cond.equals("1");

                ifStack.push(valor);
                ejecutando = valor;
            }

            case "OP_ELSE" -> {
                if (ifStack.isEmpty()) {
                    throw new InterpreterException("Se encontró OP_ELSE sin un OP_IF previo.");
                }

                boolean actual = ifStack.pop();
                boolean invertido = !actual;

                ifStack.push(invertido);
                ejecutando = invertido;
            }

            case "OP_ENDIF" -> {
                if (ifStack.isEmpty()) {
                    throw new InterpreterException("Se encontró OP_ENDIF sin un OP_IF previo.");
                }

                ifStack.pop();
                ejecutando = ifStack.isEmpty() ? true : ifStack.peek();
            }

            // MULTISIG
            case "OP_CHECKMULTISIG" -> {
                requireStackSize(1, "OP_CHECKMULTISIG");

                int n = parsePositiveInteger(stack.pop(), "OP_CHECKMULTISIG");

                if (stack.size() < n) {
                    throw new InterpreterException(
                        "No hay suficientes llaves públicas para OP_CHECKMULTISIG."
                    );
                }

                String[] pubkeys = new String[n];
                for (int i = n - 1; i >= 0; i--) {
                    pubkeys[i] = stack.pop();
                }

                requireStackSize(1, "OP_CHECKMULTISIG");
                int m = parsePositiveInteger(stack.pop(), "OP_CHECKMULTISIG");

                if (m > n) {
                    throw new InterpreterException(
                        "La cantidad de firmas requeridas no puede ser mayor que la cantidad de llaves públicas."
                    );
                }

                if (stack.size() < m) {
                    throw new InterpreterException(
                        "No hay suficientes firmas para OP_CHECKMULTISIG."
                    );
                }

                String[] sigs = new String[m];
                for (int i = m - 1; i >= 0; i--) {
                    sigs[i] = stack.pop();
                }

                int valid = 0;

                for (String sig : sigs) {
                    for (String pub : pubkeys) {
                        if (verificarFirma(sig, pub)) {
                            valid++;
                            break;
                        }
                    }
                }

                if (valid >= m) {
                    stack.push("1");
                } else {
                    failed = true;
                }
            }
            
            default -> {

                // OP_0 a OP_16 
                if (token.startsWith("OP_")) {
                    try {
                        int value = Integer.parseInt(token.substring(3));
                        if (value >= 0 && value <= 16) {
                            stack.push(String.valueOf(value));
                            return;
                        }
                    } catch (NumberFormatException ignored) {}
                }

                // Es dato (firma, pubkey, hash esperado)
                stack.push(token);
            }
        }
        
    }

    @Override
    public void reset() {
        stack.clear();
        failed = false;
        lastError = null;

        
        ejecutando = true;
        ifStack.clear();
    }

    @Override
    public String getLastError() {
        return lastError;
    }
}
