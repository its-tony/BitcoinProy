public class PruebaP2PKH {

    public static void main(String[] args) {
        boolean trace = args.length > 0 && args[0].equalsIgnoreCase("--trace");
        IOpcodeInterpreter interpreter = new Logica(trace);

        System.out.println("-- Prueba de P2PKH con el interprete --\n");

        String scriptValido =
                "SIG_PUBKEY1 PUBKEY1 " +
                "OP_DUP OP_HASH160 HASH_PUBKEY1 OP_EQUALVERIFY OP_CHECKSIG";

        String scriptHashIncorrecto =
                "SIG_PUBKEY1 PUBKEY1 " +
                "OP_DUP OP_HASH160 HASH_FAKE OP_EQUALVERIFY OP_CHECKSIG";

        String scriptFirmaIncorrecta =
                "SIG_FAKE PUBKEY1 " +
                "OP_DUP OP_HASH160 HASH_PUBKEY1 OP_EQUALVERIFY OP_CHECKSIG";

        String scriptConError = "OP_ELSE";

        ejecutarCaso(interpreter, "Caso Valido", scriptValido);
        ejecutarCaso(interpreter, "Caso Hash Incorrecto", scriptHashIncorrecto);
        ejecutarCaso(interpreter, "Caso Firma Incorrecta", scriptFirmaIncorrecta);
        ejecutarCaso(interpreter, "Caso Error de Script", scriptConError);
    }

    private static void ejecutarCaso(IOpcodeInterpreter interpreter, String titulo, String script) {
        System.out.println("-- " + titulo + " --");
        System.out.println("Script: " + script);

        boolean resultado = interpreter.execute(script);
        System.out.println("Resultado: " + resultado);

        if (!resultado && interpreter.getLastError() != null) {
            System.out.println("Error del interprete: " + interpreter.getLastError());
        }

        System.out.println();
    }
}
