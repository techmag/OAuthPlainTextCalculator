class OAuthPlainTextCalculator(consumerKey: ConsumerKey, requestToken: RequestToken) extends WSSignatureCalculator with com.ning.http.client.SignatureCalculator {
  import com.ning.http.client.{ Request, RequestBuilderBase }
  import com.ning.http.util.UTF8UrlEncoder
  import com.ning.http.util.Base64

  val HEADER_AUTHORIZATION = "Authorization"
  val KEY_OAUTH_CONSUMER_KEY = "oauth_consumer_key"
  val KEY_OAUTH_NONCE = "oauth_nonce"
  val KEY_OAUTH_SIGNATURE = "oauth_signature"
  val KEY_OAUTH_SIGNATURE_METHOD = "oauth_signature_method"
  val KEY_OAUTH_TIMESTAMP = "oauth_timestamp"
  val KEY_OAUTH_TOKEN = "oauth_token"
  val KEY_OAUTH_VERSION = "oauth_version"

  val OAUTH_VERSION_1_0 = "1.0"
  val OAUTH_SIGNATURE_METHOD = "PLAINTEXT"

  protected final val nonceBuffer: Array[Byte] = new Array[Byte](16)

  override def calculateAndAddSignature(request: Request, requestBuilder: RequestBuilderBase[_]): Unit = {
    val nonce: String = generateNonce
    val timestamp: Long = System.currentTimeMillis() / 1000L
    val signature = calculateSignature(request.getMethod, request.getUrl, timestamp, nonce, request.getFormParams, request.getQueryParams)
    val headerValue = constructAuthHeader(signature, nonce, timestamp)
    requestBuilder.setHeader(HEADER_AUTHORIZATION, headerValue);
  }

  /**
   * from http://oauth.net/core/1.0/#signing_process
   * oauth_signature is set to the concatenated encoded values of the
   * Consumer Secret and Token Secret,
   * separated by a ‘&’ character (ASCII code 38),
   * even if either secret is empty.
   * The result MUST be encoded again.
   */

  def calculateSignature(method: String, baseURL: String, oauthTimestamp: Long, nonce: String, formParams: java.util.List[com.ning.http.client.Param], queryParams: java.util.List[com.ning.http.client.Param]) = {
    val signedText = new StringBuilder(100)
    signedText.append(consumerKey.secret)
    signedText.append('&');
    signedText.append(requestToken.secret)
    UTF8UrlEncoder.encode(signedText.toString)
  }

  def constructAuthHeader(signature: String, nonce: String, oauthTimestamp: Long, sb: StringBuilder = new StringBuilder) = {
    constructAuthHeader_sb(signature, nonce, oauthTimestamp).toString
  }

  def constructAuthHeader_sb(signature: String, nonce: String, oauthTimestamp: Long, sb: StringBuilder = new StringBuilder(250)) = {
    sb.synchronized {
      sb.append("OAuth ")

      sb.append(KEY_OAUTH_CONSUMER_KEY)
      sb.append("=\"")
      sb.append(consumerKey.key)
      sb.append("\", ")

      sb.append(KEY_OAUTH_TOKEN)
      sb.append("=\"")
      sb.append(requestToken.token)
      sb.append("\", ")

      sb.append(KEY_OAUTH_SIGNATURE_METHOD)
      sb.append("=\"")
      sb.append(OAUTH_SIGNATURE_METHOD)
      sb.append("\", ")

      // careful: base64 has chars that need URL encoding:
      sb.append(KEY_OAUTH_SIGNATURE)
      sb.append("=\"");
      sb.append(signature)
      sb.append("\", ")

      sb.append(KEY_OAUTH_TIMESTAMP)
      sb.append("=\"")
      sb.append(oauthTimestamp)
      sb.append("\", ")

      // also: nonce may contain things that need URL encoding (esp. when using base64):
      sb.append(KEY_OAUTH_NONCE)
      sb.append("=\"");
      sb.append(UTF8UrlEncoder.encode(nonce))
      sb.append("\", ")

      sb.append(KEY_OAUTH_VERSION)
      sb.append("=\"")
      sb.append(OAUTH_VERSION_1_0)
      sb.append("\"")
      sb
    }
  }

  def generateNonce = synchronized {
    scala.util.Random.nextBytes(nonceBuffer)
    // let's use base64 encoding over hex, slightly more compact than hex or decimals
    Base64.encode(nonceBuffer)
  }
}

object OAuthPlainTextCalculator {
  def apply(consumerKey: ConsumerKey, token: RequestToken): WSSignatureCalculator = {
    new OAuthPlainTextCalculator(consumerKey, token)
  }
}
