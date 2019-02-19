package com.github.megatronking.netbare;

import com.google.common.io.CharStreams;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * A collection of assorted encryption-utility classes.
 *
 * @author José Luis Ametller
 * @since 2019-02-04 15:16
 */
public final class NetBareEncryptionUtils {
	public static PrivateKey decodePemEncodedPrivateKey(Reader privateKeyReader, String password) {
		try (PEMParser pemParser = new PEMParser(privateKeyReader)) {
			Object keyPair = pemParser.readObject();

			// retrieve the PrivateKeyInfo from the returned keyPair object. if the key is encrypted, it needs to be
			// decrypted using the specified password first.
			PrivateKeyInfo keyInfo;
			if (keyPair instanceof PEMEncryptedKeyPair) {
				if (password == null) {
					throw new NetBareImportException("Unable to import private key. Key is encrypted, but no password was provided.");
				}

				PEMDecryptorProvider decryptor = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());

				PEMKeyPair decryptedKeyPair = ((PEMEncryptedKeyPair) keyPair).decryptKeyPair(decryptor);

				keyInfo = decryptedKeyPair.getPrivateKeyInfo();
			} else {
				keyInfo = ((PEMKeyPair) keyPair).getPrivateKeyInfo();
			}

			return new JcaPEMKeyConverter().getPrivateKey(keyInfo);
		} catch (IOException e) {
			throw new NetBareImportException("Unable to read PEM-encoded PrivateKey", e);
		}
	}

	public static X509Certificate decodePemEncodedCertificate(Reader certificateReader) {
		// JCA supports reading PEM-encoded X509Certificates fairly easily, so there is no need to use BC to read the cert
		Certificate certificate;

		// the JCA CertificateFactory takes an InputStream, so convert the reader to a stream first. converting to a String first
		// is not ideal, but is relatively straightforward. (PEM certificates should only contain US_ASCII-compatible characters.)
		try (InputStream certificateAsStream = new ByteArrayInputStream(CharStreams.toString(certificateReader).getBytes(StandardCharsets.US_ASCII))) {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			certificate = certificateFactory.generateCertificate(certificateAsStream);
		} catch (CertificateException | IOException e) {
			throw new NetBareImportException("Unable to read PEM-encoded X509Certificate", e);
		}

		if (!(certificate instanceof X509Certificate)) {
			throw new NetBareImportException("Attempted to import non-X.509 certificate as X.509 certificate");
		}

		return (X509Certificate) certificate;
	}
}
