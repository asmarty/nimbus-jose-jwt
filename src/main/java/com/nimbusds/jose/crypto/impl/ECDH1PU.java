/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.crypto.impl;


import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;


/**
 * Elliptic Curve Diffie-Hellman One-Pass Unified Model (ECDH-1PU)
 * key agreement functions and utilities.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04">Public Key Authenticated Encryption for JOSE: ECDH-1PU</a>
 *
 * @author Alexander Martynov
 * @version 2021-08-03
 */
public class ECDH1PU {

	/**
	 * Resolves the ECDH algorithm mode.
	 *
	 * @param alg The JWE algorithm. Must be supported and not
	 *            {@code null}.
	 *
	 * @return The algorithm mode.
	 *
	 * @throws JOSEException If the JWE algorithm is not supported.
	 */
	public static ECDH.AlgorithmMode resolveAlgorithmMode(final JWEAlgorithm alg)
		throws JOSEException {

		if (alg.equals(JWEAlgorithm.ECDH_1PU)) {

			return ECDH.AlgorithmMode.DIRECT;

		} else if (alg.equals(JWEAlgorithm.ECDH_1PU_A128KW) ||
				alg.equals(JWEAlgorithm.ECDH_1PU_A192KW) ||
				alg.equals(JWEAlgorithm.ECDH_1PU_A256KW)
		) {

			return ECDH.AlgorithmMode.KW;
		} else {

			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(
				alg,
				ECDHCryptoProvider.SUPPORTED_ALGORITHMS));
		}
	}


	/**
	 * Returns the bit length of the shared key (derived via concat KDF)
	 * for the specified JWE ECDH algorithm.
	 *
	 * @param alg The JWE ECDH algorithm. Must be supported and not
	 *            {@code null}.
	 * @param enc The encryption method. Must be supported} and not
	 *            {@code null}.
	 *
	 * @return The bit length of the shared key.
	 *
	 * @throws JOSEException If the JWE algorithm or encryption method is
	 *                       not supported.
	 */
	public static int sharedKeyLength(final JWEAlgorithm alg, final EncryptionMethod enc)
		throws JOSEException {

		if (alg.equals(JWEAlgorithm.ECDH_1PU)) {

			int length = enc.cekBitLength();

			if (length == 0) {
				throw new JOSEException("Unsupported JWE encryption method " + enc);
			}

			return length;

		} else if (alg.equals(JWEAlgorithm.ECDH_1PU_A128KW)) {
			return 128;
		} else if (alg.equals(JWEAlgorithm.ECDH_1PU_A192KW)) {
			return  192;
		} else if (alg.equals(JWEAlgorithm.ECDH_1PU_A256KW)) {
			return  256;
		} else {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(
				alg, ECDHCryptoProvider.SUPPORTED_ALGORITHMS));
		}
	}

	/**
	 * Derives a shared key (via concat KDF).
	 *
	 * @param header    The JWE header. Its algorithm and encryption method
	 *                  must be supported. Must not be {@code null}.
	 * @param Z         The derived shared secret ('Z'). Must not be
	 *                  {@code null}.
	 * @param concatKDF The concat KDF. Must be initialised and not
	 *                  {@code null}.
	 *
	 * @return The derived shared key.
	 *
	 * @throws JOSEException If derivation of the shared key failed.
	 */
	public static SecretKey deriveSharedKey(final JWEHeader header,
											final SecretKey Z,
											final ConcatKDF concatKDF)
			throws JOSEException {

		final int sharedKeyLength = sharedKeyLength(header.getAlgorithm(), header.getEncryptionMethod());

		// Set the alg ID for the concat KDF
		ECDH.AlgorithmMode algMode = resolveAlgorithmMode(header.getAlgorithm());

		final String algID;

		if (algMode == ECDH.AlgorithmMode.DIRECT) {
			// algID = enc
			algID = header.getEncryptionMethod().getName();
		} else if (algMode == ECDH.AlgorithmMode.KW) {
			// algID = alg
			algID = header.getAlgorithm().getName();
		} else {
			throw new JOSEException("Unsupported JWE ECDH algorithm mode: " + algMode);
		}

		return concatKDF.deriveKey(
				Z,
				sharedKeyLength,
				ConcatKDF.encodeDataWithLength(algID.getBytes(StandardCharsets.US_ASCII)),
				ConcatKDF.encodeDataWithLength(header.getAgreementPartyUInfo()),
				ConcatKDF.encodeDataWithLength(header.getAgreementPartyVInfo()),
				ConcatKDF.encodeIntData(sharedKeyLength),
				ConcatKDF.encodeNoData()
		);
	}

	/**
	 * Derives a shared key (via concat KDF).
	 *
	 * @param header    The JWE header. Its algorithm and encryption method
	 *                  must be supported. Must not be {@code null}.
	 * @param Z         The derived shared secret ('Z'). Must not be
	 *                  {@code null}.
	 * @param tag       In Direct Key Agreement mode this is set to an empty octet
	 *       			string. In Key Agreement with Key Wrapping mode, this is set to a
	 *       			value of the form Data, where Data is the raw octets of
	 *       			the JWE Authentication Tag.
	 * @param concatKDF The concat KDF. Must be initialised and not
	 *                  {@code null}.
	 *
	 * @return The derived shared key.
	 *
	 * @throws JOSEException If derivation of the shared key failed.
	 */
	public static SecretKey deriveSharedKey(final JWEHeader header,
						final SecretKey Z,
						final Base64URL tag,
						final ConcatKDF concatKDF)
		throws JOSEException {

		final int sharedKeyLength = sharedKeyLength(header.getAlgorithm(), header.getEncryptionMethod());

		// Set the alg ID for the concat KDF
		ECDH.AlgorithmMode algMode = resolveAlgorithmMode(header.getAlgorithm());

		final String algID;

		if (algMode == ECDH.AlgorithmMode.DIRECT) {
			// algID = enc
			algID = header.getEncryptionMethod().getName();
		} else if (algMode == ECDH.AlgorithmMode.KW) {
			// algID = alg
			algID = header.getAlgorithm().getName();
		} else {
			throw new JOSEException("Unsupported JWE ECDH algorithm mode: " + algMode);
		}

		return concatKDF.deriveKey(
			Z,
			sharedKeyLength,
			ConcatKDF.encodeDataWithLength(algID.getBytes(StandardCharsets.US_ASCII)),
			ConcatKDF.encodeDataWithLength(header.getAgreementPartyUInfo()),
			ConcatKDF.encodeDataWithLength(header.getAgreementPartyVInfo()),
			ConcatKDF.encodeIntData(sharedKeyLength),
			ConcatKDF.encodeNoData(),
            ConcatKDF.encodeDataWithLength(tag)
		);
	}

	/**
	 * Derives a shared secret (also called 'Z') where Z is the
	 * concatenation of Ze and Zs.
	 *
	 * @param Ze	The shared secret derived from applying the ECDH primitive
	 *              to the sender's ephemeral private key and the recipient's
	 *              static public key (when sending) or the recipient's
	 *              static private key and the sender's ephemeral public
	 *       	 	key (when receiving) Must not be {@code null}.
	 * @param Zs 	The shared secret derived from
	 *       		applying the ECDH primitive to the sender's static private key and
	 *       		the recipient's static public key (when sending) or the
	 *       		recipient's static private key and the sender's static public key
	 *       		(when receiving). Must not be {@code null}.
	 * @return		The derived shared key.
	 */
	public static SecretKey deriveZ(final SecretKey Ze, final SecretKey Zs) {
		byte[] encodedKey = ByteUtils.concat(Ze.getEncoded(), Zs.getEncoded());
		return new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
	}

	/**
	 * Prevents public instantiation.
	 */
	private ECDH1PU() {

	}
}