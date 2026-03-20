import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class InterpreterTest {

    // P2PKH Válido
    @Test
    void p2pkhValidoDebePasar() {
        IOpcodeInterpreter interpreter = new Logica(false);

        String script = "SIG_PUBKEY1 PUBKEY1 OP_DUP OP_HASH160 HASH_PUBKEY1 OP_EQUALVERIFY OP_CHECKSIG";

        assertTrue(interpreter.execute(script));
    }

    // Hash Inválido
    @Test
    void p2pkhHashIncorrectoDebeFallar() {
        IOpcodeInterpreter interpreter = new Logica(false);

        String script = "SIG_PUBKEY1 PUBKEY1 OP_DUP OP_HASH160 HASH_FAKE OP_EQUALVERIFY OP_CHECKSIG";

        assertFalse(interpreter.execute(script));
    }

    // Firma Inválida
    @Test
    void p2pkhFirmaIncorrectaDebeFallar() {
        IOpcodeInterpreter interpreter = new Logica(false);

        String script = "SIG_FAKE PUBKEY1 OP_DUP OP_HASH160 HASH_PUBKEY1 OP_EQUALVERIFY OP_CHECKSIG";

        assertFalse(interpreter.execute(script));
    }

    // Stack Vacío
    @Test
    void stackVacioDebeFallar() {
        IOpcodeInterpreter interpreter = new Logica(false);

        String script = "OP_CHECKSIG";

        assertFalse(interpreter.execute(script));
    }

    // OP_DUP Sin Elementos
    @Test
    void opDupSinElementosDebeFallar() {
        IOpcodeInterpreter interpreter = new Logica(false);

        String script = "OP_DUP";

        assertFalse(interpreter.execute(script));
    }

    // OP_EQUALVERIFY Fallando
    @Test
    void equalVerifyDebeFallarSiNoSonIguales() {
        IOpcodeInterpreter interpreter = new Logica(false);

        String script = "A B OP_EQUALVERIFY";

        assertFalse(interpreter.execute(script));
    }

    // ✅ OP_EQUALVERIFY Correcto
    @Test
    void equalVerifyDebePasarSiSonIguales() {
        IOpcodeInterpreter interpreter = new Logica(false);

        String script = "A A OP_EQUALVERIFY OP_1";

        assertTrue(interpreter.execute(script));
    }
}