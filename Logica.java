import java.util.ArrayDeque;
import java.util.Deque;
public class Logica implements IOpcodeInterpreter {

    private final Stack stack;
    private final boolean trace;
    private boolean failed;

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

        String[] tokens = script.split("\\s+");

        for (String token : tokens) {

            // NUEVO (control de ejecución condicional)
            if (!ejecutando &&
                !token.equals("OP_IF") &&
                !token.equals("OP_ELSE") &&
                !token.equals("OP_ENDIF")) {
                continue;
            }

            processToken(token);

            if (failed) {
                return false; // fallo inmediato
            }

            if (trace) {
                System.out.println("Token: " + token);
                System.out.println("Stack: " + stack);
                System.out.println("------------------");
            }
        }

        // Resultado
        return !stack.isEmpty() && stack.pop().equals("1");
    }

    private boolean verificarFirma(String sig, String pubkey) {
        return sig.equals("SIG_" + pubkey);
    }

    @Override
    public void processToken(String token) {

        switch (token) {

            case "OP_DUP" -> {
                if (stack.size() < 1) {
                    failed = true;
                    return;
                }
                stack.push(stack.peek());
            }

            case "OP_DROP" -> {
                if (stack.size() < 1) {
                    failed = true;
                    return;
                }
                stack.pop();
            }

            case "OP_HASH160" -> {
                if (stack.size() < 1) {
                    failed = true;
                    return;
                }
                String value = stack.pop();
                stack.push("HASH_" + value); 
            }

            case "OP_EQUAL" -> {
                if (stack.size() < 2) {
                    failed = true;
                    return;
                }

                String b = stack.pop();
                String a = stack.pop();

                if (a.equals(b)) {
                    stack.push("1");
                } else {
                    stack.push("0");
                }
            }

            case "OP_EQUALVERIFY" -> {
                if (stack.size() < 2) {
                    failed = true;
                    return;
                }

                String b = stack.pop();
                String a = stack.pop();

                if (!a.equals(b)) {
                    failed = true; // fallo inmediato
                }
            }

            case "OP_CHECKSIG" -> {
                if (stack.size() < 2) {
                    failed = true;
                    return;
                }

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
                if (stack.size() < 1) {
                    failed = true;
                    return;
                }

                String cond = stack.pop();
                boolean valor = cond.equals("1");

                ifStack.push(valor);
                ejecutando = valor;
            }

            case "OP_ELSE" -> {
                if (ifStack.isEmpty()) {
                    failed = true;
                    return;
                }

                boolean actual = ifStack.pop();
                boolean invertido = !actual;

                ifStack.push(invertido);
                ejecutando = invertido;
            }

            case "OP_ENDIF" -> {
                if (ifStack.isEmpty()) {
                    failed = true;
                    return;
                }

                ifStack.pop();
                ejecutando = ifStack.isEmpty() ? true : ifStack.peek();
            }

            // MULTISIG
            case "OP_CHECKMULTISIG" -> {
                if (stack.size() < 1) {
                    failed = true;
                    return;
                }

                int n = Integer.parseInt(stack.pop());

                if (stack.size() < n) {
                    failed = true;
                    return;
                }

                String[] pubkeys = new String[n];
                for (int i = n - 1; i >= 0; i--) {
                    pubkeys[i] = stack.pop();
                }

                int m = Integer.parseInt(stack.pop());

                if (stack.size() < m) {
                    failed = true;
                    return;
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

        
        ejecutando = true;
        ifStack.clear();
    }
}