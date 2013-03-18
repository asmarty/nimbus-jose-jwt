package com.nimbusds.jose.jwk;


import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * Public and private {@link KeyType#RSA RSA} JSON Web Key (JWK). This class is
 * immutable.
 *
 * <p>Example JSON object representation of a public RSA JWK:
 *
 * <pre>
 * { 
 *   "kty" : "RSA",
 *   "n"   : "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
 *            4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
 *            tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
 *            QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
 *            SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
 *            w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
 *   "e"   : "AQAB",
 *   "alg" : "RS256",
 *   "kid" : "2011-04-29"
 * }
 * </pre>
 *
 * <p>See http://en.wikipedia.org/wiki/RSA_%28algorithm%29
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version $version$ (2013-03-15)
 */
@Immutable
public final class RSAKey extends JWK {


	/**
	 * Other Primes Info, represents the private {@code oth} parameter of a
	 * RSA key. This class is immutable.
	 *
	 * @author Justin Richer
	 */
	@Immutable
	public static class OtherRSAPrimesInfo {


		 /**
	          * The prime factor.
	          */
		private final Base64URL r;

		
		/**
		 * The factor Chinese Remainder Theorem (CRT) exponent.
		 */
    		private final Base64URL d;
    	

		/**
		 * The factor Chinese Remainder Theorem (CRT) coefficient.
		 */
		private final Base64URL t;


		/**
		 * Creates a new Other Primes Info with the specified 
		 * parameters.
		 *
		 * @param r The prime factor. Must not be {@code null}.
		 * @param d The factor Chinese Remainder Theorem (CRT) 
		 *          exponent. Must not be {@code null}.
		 * @param t The factor Chinese Remainder Theorem (CRT) 
		 *          coefficient. Must not be {@code null}.
		 */
		public OtherRSAPrimesInfo(Base64URL r, Base64URL d, Base64URL t) {

			if (r == null) {

				throw new IllegalArgumentException("The prime factor must not be null");
			}

			this.r = r;

			if (d == null) {

				throw new IllegalArgumentException("The factor CRT exponent must not be null");
			}

			this.d = d;

			if (t == null) {

				throw new IllegalArgumentException("The factor CRT coefficient must not be null");
			}
			
			this.t = t;
		}
       
    	
		/**
		 * Gets the prime factor.
		 *
		 * @return The prime factor.
		 */
		public Base64URL getPrimeFactor() {

			return r;
		}


		/**
		 * Gets factor Chinese Remainder Theorem (CRT) exponent.
		 *
		 * @return The factor Chinese Remainder Theorem (CRT) exponent.
		 */
		public Base64URL getFactorCRTExponent() {

			return d;
		}


		/**
		 * The factor Chinese Remainder Theorem (CRT) coefficient.
		 *
		 * @return The factor Chinese Remainder Theorem (CRT) 
		 *         coefficient.
		 */
		public Base64URL getFactorCRTCoefficient() {

			return t;
		}
	}


	/**
	 * The modulus value for the RSA public key.
	 */
	private final Base64URL n;


	/**
	 * The exponent value for the RSA public key.
	 */
	private final Base64URL e;
	

	/**
	 * The private exponent of the private RSA key.
	 */
	private final Base64URL d;

	
	/**
	 * The first prime factor of the private RSA key.
	 */
	private final Base64URL p;

	
	/**
	 * The second prime factor of the private RSA key.
	 */
	private final Base64URL q;

	
	/**
	 * The first factor Chinese Remainder Theorem exponent of the private 
	 * RSA key.
	 */
	private final Base64URL dp;

	
	/**
	 * The second factor Chinese Remainder Theorem exponent of the private
	 * RSA key.
	 */
	private final Base64URL dq;

	
	/**
	 * The first Chinese Remainder Theorem coefficient of the private RSA
	 * key.
	 */
	private final Base64URL qi;

	
	/**
	 * The other primes information of the private RSA key, should the
	 * exist. When only two primes have been used (the normal case), this 
	 * parameter MUST be omitted. When three or more primes have been used,
	 * the number of array elements MUST be the number of primes used minus
	 * two. Each array element MUST be an object with the following 
	 * members:
	 */
	private final List<OtherRSAPrimesInfo> oth;


	/**
	 * Creates a new public RSA JSON Web Key (JWK) with the specified 
	 * parameters.
	 *
	 * @param n   The the modulus value for the RSA public key. It is 
	 *            represented as the Base64URL encoding of value's big 
	 *            endian representation. Must not be {@code null}.
	 * @param e   The exponent value for the RSA public key. It is 
	 *            represented as the Base64URL encoding of value's big 
	 *            endian representation. Must not be {@code null}.
	 * @param use The key use. {@code null} if not specified.
	 * @param alg The intended JOSE algorithm for the key, {@code null} if
	 *            not specified.
	 * @param kid The key ID. {@code null} if not specified.
	 */
	public RSAKey(final Base64URL n, final Base64URL e, final Use use, 
		      final Algorithm alg, final String kid) {

		// call the full constructor
		// all private key parameters are null
		this(n, e, null, null, null, null, null, null, null, use, alg, kid);
	}


	/**
	 * Creates a new public / private RSA JSON Web Key (JWK) with the 
	 * specified parameters. The private RSA key is specified by its first
	 * representation (see RFC 3447, section 3.2).
	 * 
	 * @param n   The the modulus value for the RSA public key. It is
	 *            represented as the Base64URL encoding of value's big 
	 *            endian representation. Must not be {@code null}.
	 * @param e   The exponent value for the RSA public key. It is 
	 *            represented as the Base64URL encoding of value's big 
	 *            endian representation. Must not be {@code null}.
	 * @param d   The private exponent. It is represented as the Base64URL 
	 *            encoding of the value's big endian representation. Must 
	 *            not be {@code null}.
	 * @param use The key use. {@code null} if not specified.
	 * @param alg The intended JOSE algorithm for the key, {@code null} if 
	 *            not specified.
	 * @param kid The key ID, {@code null} if not specified.
	 */
	public RSAKey(final Base64URL n, final Base64URL e, final Base64URL d,
		          final Use use, final Algorithm alg, final String kid) {
	    
		// call the full constructor
		// The first second representation parameters are all null
		this(n, e, d, null, null, null, null, null, null, use, alg, kid);

		if (d == null) {
			throw new IllegalArgumentException("The private exponent must not be null");
		}
			
	}

	/**
	 * Creates a new public / private RSA JSON Web Key (JWK) with the 
	 * specified parameters. The private RSA key is specified by its
	 * second representation (see RFC 3447, section 3.2).
	 * 
	 * @param n   The the modulus value for the RSA public key. It is
	 *            represented as the Base64URL encoding of value's big 
	 *            endian representation. Must not be {@code null}.
	 * @param e   The exponent value for the RSA public key. It is 
	 *            represented as the Base64URL encoding of value's big 
	 *            endian representation. Must not be {@code null}.
	 * @param p   The first prime factor. It is represented as the 
	 *            Base64URL encoding of the value's big endian 
	 *            representation. Must not be {@code null}.
	 * @param q   The second prime factor. It is represented as the 
	 *            Base64URL encoding of the value's big endian 
	 *            representation. Must not be {@code null}.
	 * @param dp  The first factor Chinese Remainder Theorem exponent. It 
	 *            is represented as the Base64URL encoding of the value's 
	 *            big endian representation. Must not be {@code null}.
	 * @param dq  The second factor Chinese Remainder Theorem exponent. It 
	 *            is represented as the Base64URL encoding of the value's 
	 *            big endian representation. Must not be {@code null}.
	 * @param qi  The first Chinese Remainder Theorem coefficient. It is 
	 *            represented as the Base64URL encoding of the value's big 
	 *            endian representation. Must not be {@code null}.
	 * @param oth The other primes information, should they exist,
	 *            {@code null} or an empty list if not specified.
	 * @param use The key use. {@code null} if not specified.
	 * @param alg The intended JOSE algorithm for the key, {@code null} if 
	 *            not specified.
	 * @param kid The key ID, {@code null} if not specified.
	 */
	public RSAKey(final Base64URL n, final Base64URL e, 
		          final Base64URL p, final Base64URL q, 
		          final Base64URL dp, final Base64URL dq, final Base64URL qi, 
		          final List<OtherRSAPrimesInfo> oth,
		          final Use use, final Algorithm alg, final String kid) {
	    
		// call the full constructor
		// The first representation d param is null
		this(n, e, null, p, q, dp, dq, qi, oth, use, alg, kid);

		// catch inconsistencies
		if (p == null) {
			throw new IllegalArgumentException("The first prime factor must not be null");
		}

		if (q == null) {
			throw new IllegalArgumentException("The second prime factor must not be null");
		}

		if (dp == null) {
			throw new IllegalArgumentException("The first factor CRT exponent must not be null");
		}

		if (dq == null) {
			throw new IllegalArgumentException("The second factor CRT exponent must not be null");
		}

		if (qi == null) {
			throw new IllegalArgumentException("The first CRT coefficient must not be null");
		}
	}


	/**
	 * Helper constructor for building all possible variants of the RSA
	 * Key JWK.
	 * 
	 * Creates a new public / private RSA JSON Web Key (JWK) with the 
	 * specified parameters. The private RSA key is specified by its first
	 * and second representations (see RFC 3447, section 3.2).
	 * 
	 * @param n   The the modulus value for the RSA public key. It is
	 *            represented as the Base64URL encoding of value's big 
	 *            endian representation. Must not be {@code null}.
	 * @param e   The exponent value for the RSA public key. It is 
	 *            represented as the Base64URL encoding of value's big 
	 *            endian representation. Must not be {@code null}.
	 * @param d   The private exponent. It is represented as the Base64URL 
	 *            encoding of the value's big endian representation. May 
	 *            be {@code null}.
	 * @param p   The first prime factor. It is represented as the 
	 *            Base64URL encoding of the value's big endian 
	 *            representation. May be {@code null}.
	 * @param q   The second prime factor. It is represented as the 
	 *            Base64URL encoding of the value's big endian 
	 *            representation. May be {@code null}.
	 * @param dp  The first factor Chinese Remainder Theorem exponent. It 
	 *            is represented as the Base64URL encoding of the value's 
	 *            big endian representation. May be {@code null}.
	 * @param dq  The second factor Chinese Remainder Theorem exponent. It 
	 *            is represented as the Base64URL encoding of the value's 
	 *            big endian representation. May be {@code null}.
	 * @param qi  The first Chinese Remainder Theorem coefficient. It is 
	 *            represented as the Base64URL encoding of the value's big 
	 *            endian representation. May be {@code null}.
	 * @param oth The other primes information, should they exist,
	 *            {@code null} or an empty list if not specified.
	 * @param use The key use. {@code null} if not specified.
	 * @param alg The intended JOSE algorithm for the key, {@code null} if 
	 *            not specified.
	 * @param kid The key ID, {@code null} if not specified.
	 */
	private RSAKey(final Base64URL n, final Base64URL e, 
		          final Base64URL d, final Base64URL p, final Base64URL q, 
		          final Base64URL dp, final Base64URL dq, final Base64URL qi, 
		          final List<OtherRSAPrimesInfo> oth,
		          final Use use, final Algorithm alg, final String kid) {
	    
		super(KeyType.RSA, use, alg, kid);


		if (n == null) {
			throw new IllegalArgumentException("The modulus value must not be null");
		}

		this.n = n;


		if (e == null) {
			throw new IllegalArgumentException("The exponent value must not be null");
		}

		this.e = e;

		// the legality of these parameters are checked by their respective constructors
		this.d = d;
		this.p = p;
		this.q = q;
		this.dp = dp;
		this.dq = dq;
		this.qi = qi;
		// the other keys are always a valid list, but might be empty
		if (oth != null) {
			this.oth = Collections.unmodifiableList(oth);
		} else {
			this.oth = Collections.emptyList();
		}
		
	}

	/**
	 * Returns the modulus value of the public RSA key. It is represented
	 * as the Base64URL encoding of the value's big endian representation.
	 *
	 * @return The RSA public key modulus.
	 */
	public Base64URL getModulus() {

		return n;
	}


	/**
	 * Returns the exponent value of the public RSA key. It is represented
	 * as the Base64URL encoding of the value's big endian representation.
	 *
	 * @return The RSA public key exponent.
	 */
	public Base64URL getExponent() {

		return e;
	}


	/**
	 * Returns the private exponent of the private RSA key. It is 
	 * represented as the Base64URL encoding of the value's big endian 
	 * representation.
	 *
	 * @return The RSA private exponent, {@code null} if not specified.
	 */
	public Base64URL getPrivateExponent() {

		return d;
	}


	/**
	 * Returns the first prime factor of the private RSA key. It is 
	 * represented as the Base64URL encoding of the value's big endian 
	 * representation.
	 *
	 * @return The RSA first prime factor, {@code null} if not specified.
	 */
	public Base64URL getFirstPrimeFactor() {

		return p;
	}


	/**
	 * Returns the second prime factor of the private RSA key. It is 
	 * represented as the Base64URL encoding of the value's big endian 
	 * representation.
	 *
	 * @return The RSA second prime factor, {@code null} if not specified.
	 */
	public Base64URL getSecondPrimeFactor() {

		return q;
	}


	/**
	 * Returns the first factor Chinese Remainder Theorem (CRT) exponent of
	 * the private RSA key. It is represented as the Base64URL encoding of 
	 * the value's big endian representation.
	 *
	 * @return The RSA first factor CRT exponent, {@code null} if not 
	 *         specified.
	 */
	public Base64URL getFirstFactorCRTExponent() {

		return dp;
	}


	/**
	 * Returns the second factor Chinese Remainder Theorem (CRT) exponent 
	 * of the private RSA key. It is represented as the Base64URL encoding
	 * of the value's big endian representation.
	 *
	 * @return The RSA second factor CRT exponent, {@code null} if not
	 *         specified.
	 */
	public Base64URL getSecondFactorCRTExponent() {

		return dq;
	}


	/**
	 * Returns the first Chinese Remainder Theorem (CRT) coefficient of the
	 * private RSA key. It is represented as the Base64URL encoding of the 
	 * value's big endian representation.
	 *
	 * @return The RSA first CRT coefficient, {@code null} if not 
	 *         specified.
	 */
	public Base64URL getFirstCRTCoefficient() {

		return qi;
	}


	/**
	 * Returns the other primes information for the private RSA key, should 
	 * they exist.
	 *
	 * @return The RSA other primes information, {@code null} or empty list
	 *         if not specified.
	 */
	public List<OtherRSAPrimesInfo> getOtherPrimes() {

		return oth;
	}

	
	/**
	 * Creates a copy of the RSA public key represented by this JWK object as
	 * a native java.security.PublicKey API object.
	 * 
	 * @return The RSA public key.
	 * @throws NoSuchAlgorithmException
	 *             If the underlying system cannot create an RSA key factory
	 * @throws InvalidKeySpecException
	 *             If the key data represented here cannot be made into a valid
	 *             RSA key.
	 */
	public RSAPublicKey toRSAPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] modulusByte = getModulus().decode();
		BigInteger modulus = new BigInteger(1, modulusByte);
		byte[] exponentByte = getExponent().decode();
		BigInteger exponent = new BigInteger(1, exponentByte);
				
		RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		
		RSAPublicKey pub = (RSAPublicKey) factory.generatePublic(spec);
		
		return pub;
	}
	
	/**
	 * Creates a copy of the RSA private key represented by this JWK object as
	 * a native java.security.PrivateKey API object.
	 * 
	 * @return The RSA private key, or null if no private exponent is defined on this key.
	 * @throws NoSuchAlgorithmException
	 *             If the underlying system cannot create an RSA key factory
	 * @throws InvalidKeySpecException
	 *             If the key data represented here cannot be made into a valid
	 *             RSA key.
	 */
	public RSAPrivateKey toRSAPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		
		if (d == null) {
			// no private key
			return null;
		}
		
		byte[] modulusByte = getModulus().decode();
		BigInteger modulus = new BigInteger(1, modulusByte);		
		byte[] privateExponentByte = getPrivateExponent().decode();
		BigInteger privateExponent = new BigInteger(1, privateExponentByte);
		
		// uses plain private exponent form
		// TODO: add support for CRT-based parameter form
		RSAPrivateKeySpec spec = new RSAPrivateKeySpec(modulus, privateExponent);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		
		RSAPrivateKey priv = (RSAPrivateKey) factory.generatePrivate(spec);
		
		return priv;
	}

	/**
	 * Creates a copy of the RSA public and private keys represented by this JWK object as
	 * a native java.security.KeyPair API object.
	 * 
	 * @return The RSA private key.
	 * @throws NoSuchAlgorithmException
	 *             If the underlying system cannot create an RSA key factory
	 * @throws InvalidKeySpecException
	 *             If the key data represented here cannot be made into a valid
	 *             RSA key.
	 */
	public KeyPair toKeyPair() throws NoSuchAlgorithmException, InvalidKeySpecException {
		return new KeyPair(toRSAPublicKey(), toRSAPrivateKey());
	}

	/**
	 * Creates a copy of this RSAKey object with any private values removed.
	 * @return the copied public RSA key
	 */
	@Override
	public RSAKey toPublicJWK() {
		return new RSAKey(getModulus(), getExponent(), getKeyUse(), getAlgorithm(), getKeyID());
	}
	
	/**
	 * Creates a new public RSA JSON Web Key (JWK) with the specified
	 * parameters.
	 * 
	 * @param pub
	 *            The RSA Public Key to represent. Must not be {@code null}.
	 * @param use
	 *            The key use. {@code null} if not specified.
	 * @param alg
	 *            The intended JOSE algorithm for the key, {@code null} if not
	 *            specified.
	 * @param kid
	 *            The key ID. {@code null} if not specified.
	 */
	public static RSAKey fromRSAPublicKey(final RSAPublicKey pub,
		      final Use use, final Algorithm alg, final String kid 
			) {
		
		if (pub == null) {
			throw new IllegalArgumentException("Public key must not be null.");
		}
		
		return new RSAKey(Base64URL.encode(pub.getModulus().toByteArray()), Base64URL.encode(pub.getPublicExponent().toByteArray()), 
				use, alg, kid);
	}

	/**
	 * Creates a new public/private RSA JSON Web Key (JWK) with the specified
	 * parameters.
	 * 
	 * @param pub
	 *            The RSA Public Key to represent. Must not be {@code null}.
	 * @param priv
	 *            The RSA Private Key to represent. Must not be {@code null}.
	 * @param use
	 *            The key use. {@code null} if not specified.
	 * @param alg
	 *            The intended JOSE algorithm for the key, {@code null} if not
	 *            specified.
	 * @param kid
	 *            The key ID. {@code null} if not specified.
	 */
	public static RSAKey fromRSAPublicPrivateKey(final RSAPublicKey pub, final RSAPrivateKey priv,
		      final Use use, final Algorithm alg, final String kid 
			) {
		
		if (pub == null) {
			throw new IllegalArgumentException("Public key must not be null.");
		}
		
		if (priv == null) {
			throw new IllegalArgumentException("Private key must not be null.");
		}
		
		return new RSAKey(Base64URL.encode(pub.getModulus().toByteArray()), Base64URL.encode(pub.getPublicExponent().toByteArray()), 
				Base64URL.encode(priv.getPrivateExponent().toByteArray()),
				use, alg, kid);
	}
	
	
	@Override
	public JSONObject toJSONObject() {

		JSONObject o = super.toJSONObject();

		// Append RSA public key specific attributes
		o.put("n", n.toString());
		o.put("e", e.toString());
		if (d != null) {
			o.put("d", d.toString());
		}
		if (p != null) {
			o.put("p", p.toString());
		}
		if (q != null) {
			o.put("q", q.toString());
		}
		if (dp != null) {
			o.put("dp", dp.toString());
		}
		if (dq != null) {
			o.put("dq", dq.toString());
		}
		if (qi != null) {
			o.put("qi", qi.toString());
		}
		if (oth != null && !oth.isEmpty()) {

			JSONArray a = new JSONArray();

			for (OtherRSAPrimesInfo other : oth) {

				JSONObject oo = new JSONObject();
				oo.put("r", other.r.toString());
				oo.put("d", other.d.toString());
				oo.put("t", other.t.toString());

				a.add(oo);
			}

			o.put("oth", a);
		}

		return o;
	}


	/**
	 * Parses a public / private RSA JWK from the specified JSON object 
	 * representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   @code null}.
	 *
	 * @return The public /private RSA Key.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to 
	 *                        valid RSA JWK.
	 */
	public static RSAKey parse(final JSONObject jsonObject)
			throws ParseException {

		// Parse the mandatory public key parameters first
		Base64URL n = new Base64URL(JSONObjectUtils.getString(jsonObject, "n"));
		Base64URL e = new Base64URL(JSONObjectUtils.getString(jsonObject, "e"));

		// Check key type
		KeyType kty = KeyType.parse(JSONObjectUtils.getString(jsonObject, "kty"));
		if (kty != KeyType.RSA) {
			throw new ParseException("The key type \"kty\" must be RSA", 0);
		}
		
		// parse the optional private key parameters
		Base64URL d = null;
		if (jsonObject.get("d") != null) {
			d = new Base64URL(JSONObjectUtils.getString(jsonObject, "d"));
		}
		Base64URL p = null;
		if (jsonObject.get("p") != null) {
			p = new Base64URL(JSONObjectUtils.getString(jsonObject, "p"));
		}
		Base64URL q = null;
		if (jsonObject.get("q") != null) {
			q = new Base64URL(JSONObjectUtils.getString(jsonObject, "q"));
		}
		Base64URL dp = null;
		if (jsonObject.get("dp") != null) {
			dp = new Base64URL(JSONObjectUtils.getString(jsonObject, "dp"));
		}
		Base64URL dq= null;
		if (jsonObject.get("dq") != null) {
			dq = new Base64URL(JSONObjectUtils.getString(jsonObject, "dq"));
		}
		Base64URL qi = null;
		if (jsonObject.get("qi") != null) {
			qi = new Base64URL(JSONObjectUtils.getString(jsonObject, "qi"));
		}
		
		List<OtherRSAPrimesInfo> oth = null;
		if (jsonObject.get("oth") != null) {

			JSONArray arr = JSONObjectUtils.getJSONArray(jsonObject, "oth");
			oth = new ArrayList<RSAKey.OtherRSAPrimesInfo>(arr.size());
			
			for (Object o : arr) {

				if (o instanceof JSONObject) {
					JSONObject otherJson = (JSONObject)o;

					Base64URL r = new Base64URL(JSONObjectUtils.getString(otherJson, "r"));
					Base64URL odq = new Base64URL(JSONObjectUtils.getString(otherJson, "dq"));
					Base64URL t = new Base64URL(JSONObjectUtils.getString(otherJson, "t"));

					OtherRSAPrimesInfo prime = new OtherRSAPrimesInfo(r, odq, t);
					oth.add(prime);
				}
			}
		}
		
		// Get optional key use
		Use use = JWK.parseKeyUse(jsonObject);

		// Get optional intended algorithm
		Algorithm alg = JWK.parseAlgorithm(jsonObject);

		// Get optional key ID
		String kid = JWK.parseKeyID(jsonObject);

		return new RSAKey(n, e, d, p, q, dp, dq, qi, oth, use, alg, kid);
	}
}