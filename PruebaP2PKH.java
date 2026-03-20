public class PruebaP2PKH {

    public static void main(String[] args) {

        IOpcodeInterpreter interpreter = new Logica(true);

        System.out.println("-- Prueba de P2PKH --\n");

        // Caso Válido
        String scriptValido =
                "SIG_VALIDA PUBKEY1 " +
                "OP_DUP OP_HASH160 HASH_PUBKEY1 OP_EQUALVERIFY OP_CHECKSIG";

        System.out.println("-- Caso Válido --");
        boolean resultadoValido = interpreter.execute(scriptValido);
        System.out.println("Resultado: " + resultadoValido);
        System.out.println();

        // Caso inválido (Hash Incorrecto)
        String scriptHashIncorrecto =
                "SIG_VALIDA PUBKEY1 " +
                "OP_DUP OP_HASH160 HASH_FAKE OP_EQUALVERIFY OP_CHECKSIG";

        System.out.println("-- Caso Hash Incorrecto --");
        boolean resultadoHash = interpreter.execute(scriptHashIncorrecto);
        System.out.println("Resultado: " + resultadoHash);
        System.out.println();

        // Caso Inválido (Firma Incorrecta)
        String scriptFirmaIncorrecta =
                "SIG_INVALIDA PUBKEY1 " +
                "OP_DUP OP_HASH160 HASH_PUBKEY1 OP_EQUALVERIFY OP_CHECKSIG";

        System.out.println("-- Caso Firma Incorrecta --");
        boolean resultadoFirma = interpreter.execute(scriptFirmaIncorrecta);
        System.out.println("Resultado: " + resultadoFirma);
        System.out.println();
    }
}