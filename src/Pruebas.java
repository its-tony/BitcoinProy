package BitcoinProy;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class Pruebas {

    @BeforeAll
    static void configurarProveedor() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void p2pkhValidoDebePasar() throws Exception {
        KeyPair keyPair = PruebaP2PKH.generarParClaves();
        byte[] pubKeyComprimida = PruebaP2PKH.clavePublicaComprimida((BCECPublicKey) keyPair.getPublic());
        byte[] pubKeyHash160 = PruebaP2PKH.hash160(pubKeyComprimida);
        byte[] scriptPubKey = PruebaP2PKH.construirScriptPubKey(pubKeyHash160);
        byte[] txHash = PruebaP2PKH.sha256("tx_valida".getBytes(StandardCharsets.UTF_8));
        byte[] firmaDer = PruebaP2PKH.firmar(txHash, keyPair.getPrivate());
        byte[] scriptSig = PruebaP2PKH.construirScriptSig(firmaDer, pubKeyComprimida);

        boolean valido = PruebaP2PKH.verificarP2PKH(txHash, scriptSig, scriptPubKey);
        assertTrue(valido);
    }

    @Test
    void pubKeyHashIncorrectoDebeFallar() throws Exception {
        KeyPair keyPair1 = PruebaP2PKH.generarParClaves();
        KeyPair keyPair2 = PruebaP2PKH.generarParClaves();

        byte[] pub1 = PruebaP2PKH.clavePublicaComprimida((BCECPublicKey) keyPair1.getPublic());
        byte[] pub2 = PruebaP2PKH.clavePublicaComprimida((BCECPublicKey) keyPair2.getPublic());

        byte[] hashPub2 = PruebaP2PKH.hash160(pub2);
        byte[] scriptPubKeyConHashIncorrecto = PruebaP2PKH.construirScriptPubKey(hashPub2);

        byte[] txHash = PruebaP2PKH.sha256("tx_hash_incorrecto".getBytes(StandardCharsets.UTF_8));
        byte[] firmaDer = PruebaP2PKH.firmar(txHash, keyPair1.getPrivate());
        byte[] scriptSig = PruebaP2PKH.construirScriptSig(firmaDer, pub1);

        boolean valido = PruebaP2PKH.verificarP2PKH(txHash, scriptSig, scriptPubKeyConHashIncorrecto);
        assertFalse(valido);
    }

    @Test
    void firmaParaOtroMensajeDebeFallar() throws Exception {
        KeyPair keyPair = PruebaP2PKH.generarParClaves();
        byte[] pub = PruebaP2PKH.clavePublicaComprimida((BCECPublicKey) keyPair.getPublic());
        byte[] scriptPubKey = PruebaP2PKH.construirScriptPubKey(PruebaP2PKH.hash160(pub));

        byte[] txHashFirmado = PruebaP2PKH.sha256("mensaje_A".getBytes(StandardCharsets.UTF_8));
        byte[] txHashVerificado = PruebaP2PKH.sha256("mensaje_B".getBytes(StandardCharsets.UTF_8));

        byte[] firmaDer = PruebaP2PKH.firmar(txHashFirmado, keyPair.getPrivate());
        byte[] scriptSig = PruebaP2PKH.construirScriptSig(firmaDer, pub);

        boolean valido = PruebaP2PKH.verificarP2PKH(txHashVerificado, scriptSig, scriptPubKey);
        assertFalse(valido);
    }

    @Test
    void pushDataMayorA75DebeLanzarExcepcion() {
        byte[] data = new byte[76];
        Arrays.fill(data, (byte) 0x01);
        assertThrows(IllegalArgumentException.class, () -> PruebaP2PKH.pushData(data));
    }
}
