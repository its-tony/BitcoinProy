public class Logica implements IOpcodeInterpreter {

    private final Stack stack;
    private final boolean trace;
    private boolean failed;

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

            case "OP_HASH160" -> {
                if (stack.size() < 1) {
                    failed = true;
                    return;
                }
                String value = stack.pop();
                stack.push("HASH_" + value); 
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

                if (sig.contains("VALIDA")) {
                    stack.push("1");
                } else {
                    failed = true;
                }
            }

            default -> {
                // Es dato (firma, pubkey, hash esperado)
                stack.push(token);
            }
        }
    }

    @Override
    public void reset() {
        stack.clear();
        failed = false;
    }
}

