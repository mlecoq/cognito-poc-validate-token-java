package validateToken;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.codec.binary.Base64;

public class Main {

	private static String REGION = "eu-west-1";
	private static String POOL_ID = "eu-west-1_QUo7V1QpP";

	private static String iss = String.format("https://cognito-idp.%s.amazonaws.com/%s", REGION, POOL_ID);

	private static String TOKEN = "<IDTOKEN>";

	public static String getText(String url) throws Exception {
		URL website = new URL(url);
		URLConnection connection = website.openConnection();
		BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));

		StringBuilder response = new StringBuilder();
		String inputLine;

		while ((inputLine = in.readLine()) != null)
			response.append(inputLine);

		in.close();

		return response.toString();
	}

	public static void main(String[] args) throws Exception {

		ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		String jwk = getText(iss + "/.well-known/jwks.json");

		// Parse the Cognito Keys and get the key by kid
		// Key is just a class that is used for parsing JSON to POJO
		Key keys = mapper.readValue(jwk, Key.class);

		DecodedJWT decoded = JWT.decode(TOKEN);

		KeyData myKey = Arrays.asList(keys.getKeys()).stream().filter((k) -> k.getKid().equals(decoded.getKeyId()))
				.findAny().orElse(null);

		// Use Key's N and E
		BigInteger modulus = new BigInteger(1, Base64.decodeBase64(myKey.getN()));
		BigInteger exponent = new BigInteger(1, Base64.decodeBase64(myKey.getE()));

		// Create a publick key
		PublicKey publicKey = null;
		try {
			publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
		} catch (InvalidKeySpecException e) {
			// Throw error
		} catch (NoSuchAlgorithmException e) {
			// Throw error
		}

		// get an algorithm instance
		Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) publicKey, null);

		// I verify ISS field of the token to make sure it's from the Cognito source
		JWTVerifier verifier = JWT.require(algorithm).withIssuer(iss).withClaim("token_use", "id") // make sure you're verifying id		
																																										// token
				.build();

		// Verify the token
		DecodedJWT jwt = verifier.verify(TOKEN);

		// Parse various fields
		String username = jwt.getClaim("sub").asString();
		String email = jwt.getClaim("email").asString();

		System.out.println(email);
		System.out.println(username);
	}

}
