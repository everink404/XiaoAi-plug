package io.mo.xiaoaiplug.config

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.util.Base64
import org.json.JSONObject
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.ServerSocket
import java.net.URL
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.RSAPublicKeySpec
import java.util.UUID

/** Official Sign in with ChatGPT flow for a locally hosted open-source client. Tokens stay in
 * this app's private storage; the exported provider only returns completed model output. */
object ChatGptPlanAuth {
    private const val PREFS = "chatgpt_plan_auth"
    private const val ISSUER = "https://auth.openai.com"
    private const val RESOURCE = "https://api.openai.com/v1"
    private const val CALLBACK_PATH = "/auth/callback"
    private const val SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
    private val random = SecureRandom()

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun email(context: Context): String = prefs(context).getString("email", "").orEmpty()
    fun connected(context: Context): Boolean =
        prefs(context).getString("client_id", null) != null &&
            prefs(context).getString("refresh_token", null) != null &&
            prefs(context).getString("scope", "").orEmpty().split(' ').contains("chatgpt.tokens.use.direct")

    fun signOut(context: Context) {
        val p = prefs(context)
        val hostId = p.getString("host_id", null)
        p.edit().clear().apply { if (hostId != null) putString("host_id", hostId) }.commit()
    }

    /** Blocks on a background thread while the system browser completes OAuth. */
    fun signIn(context: Context): String {
        val p = prefs(context)
        val hostId = p.getString("host_id", null) ?: "urn:uuid:${UUID.randomUUID()}".also {
            p.edit().putString("host_id", it).commit()
        }
        val previousClient = p.getString("client_id", null)
        val verifier = randomUrlSafe(32)
        val challenge = b64(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray()))
        val state = randomUrlSafe(32)
        val nonce = randomUrlSafe(32)
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { listener ->
            listener.soTimeout = 120_000
            val redirect = "http://127.0.0.1:${listener.localPort}$CALLBACK_PATH"
            val params = linkedMapOf(
                "client_id" to (previousClient ?: "dynamic_agent_client"),
                "response_type" to "code", "redirect_uri" to redirect,
                "scope" to SCOPES, "resource" to RESOURCE,
                "state" to state, "nonce" to nonce,
                "code_challenge_method" to "S256", "code_challenge" to challenge,
                "ext_agent_host_id" to hostId
            )
            if (previousClient == null) params["agent_name_hint"] = "XiaoAi Plug"
            else p.getString("id_token", null)?.let { params["id_token_hint"] = it }
            val authUrl = "$ISSUER/api/accounts/authorize?${encodeForm(params)}"
            Handler(Looper.getMainLooper()).post {
                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(authUrl)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            }

            var callback: Map<String, String>? = null
            while (callback == null) {
                listener.accept().use { socket ->
                    socket.soTimeout = 10_000
                    val requestLine = socket.getInputStream().bufferedReader().readLine().orEmpty()
                    val target = requestLine.split(' ').getOrNull(1).orEmpty()
                    val path = target.substringBefore('?')
                    val page = if (path == CALLBACK_PATH) "Authorization received. Return to XiaoAi Plug." else "Unknown path."
                    val body = "<html><body>$page</body></html>".toByteArray()
                    socket.getOutputStream().write(
                        ("HTTP/1.1 ${if (path == CALLBACK_PATH) "200 OK" else "404 Not Found"}\r\n" +
                            "Content-Type: text/html; charset=utf-8\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n").toByteArray()
                    )
                    socket.getOutputStream().write(body)
                    if (path == CALLBACK_PATH) callback = decodeQuery(target.substringAfter('?', ""))
                }
            }
            val values = callback!!
            require(values["state"] == state) { "ChatGPT 授权状态不匹配" }
            values["error"]?.let { throw IllegalStateException("ChatGPT 授权被取消：$it") }
            val code = values["code"] ?: error("ChatGPT 未返回授权码")
            val clientId = values["client_id"] ?: previousClient ?: error("ChatGPT 未返回客户端 ID")
            require(previousClient == null || previousClient == clientId) { "ChatGPT 客户端 ID 不匹配" }
            val token = postForm("$ISSUER/api/accounts/oauth/token", mapOf(
                "grant_type" to "authorization_code", "client_id" to clientId,
                "code" to code, "code_verifier" to verifier,
                "redirect_uri" to redirect, "resource" to RESOURCE
            ))
            val idToken = token.getString("id_token")
            val identity = verifyIdentity(idToken, clientId, nonce)
            val subject = identity.getString("sub")
            val previousSubject = p.getString("subject", null)
            require(previousSubject == null || previousSubject == subject) { "ChatGPT 账号与原连接不一致" }
            val scope = token.optString("scope")
            require(scope.split(' ').contains("chatgpt.tokens.use.direct")) { "尚未授权使用 ChatGPT 订阅额度" }
            val refresh = token.optString("refresh_token")
            require(refresh.isNotBlank()) { "ChatGPT 未返回续期凭据" }
            val access = token.getString("access_token")
            val expiry = System.currentTimeMillis() + token.optLong("expires_in", 3600) * 1000
            val accountEmail = identity.optString("email")
            check(p.edit().putString("client_id", clientId).putString("subject", subject)
                .putString("email", accountEmail).putString("id_token", idToken)
                .putString("scope", scope).putString("access_token", access)
                .putString("refresh_token", refresh).putLong("expires_at", expiry).commit())
            return accountEmail
        }
    }

    @Synchronized
    fun accessToken(context: Context): String {
        val p = prefs(context)
        require(connected(context)) { "请先在模块内登录 ChatGPT 并授权订阅额度" }
        val current = p.getString("access_token", null)
        if (!current.isNullOrBlank() && p.getLong("expires_at", 0) > System.currentTimeMillis() + 60_000) return current
        val token = postForm("$ISSUER/api/accounts/oauth/token", mapOf(
            "grant_type" to "refresh_token",
            "client_id" to p.getString("client_id", "").orEmpty(),
            "refresh_token" to p.getString("refresh_token", "").orEmpty(),
            "resource" to RESOURCE
        ))
        val access = token.getString("access_token")
        val refresh = token.optString("refresh_token").ifBlank { p.getString("refresh_token", "").orEmpty() }
        val expiry = System.currentTimeMillis() + token.optLong("expires_in", 3600) * 1000
        check(p.edit().putString("access_token", access).putString("refresh_token", refresh)
            .putLong("expires_at", expiry).commit())
        return access
    }

    private fun verifyIdentity(jwt: String, clientId: String, nonce: String): JSONObject {
        val parts = jwt.split('.')
        require(parts.size == 3) { "无效的 ChatGPT 身份令牌" }
        val header = JSONObject(String(unb64(parts[0])))
        require(header.optString("alg") == "RS256") { "不支持的 ChatGPT 签名算法" }
        val kid = header.getString("kid")
        val jwks = JSONObject(getText("$ISSUER/.well-known/jwks.json"))
        val keys = jwks.getJSONArray("keys")
        val key = (0 until keys.length()).map { keys.getJSONObject(it) }.firstOrNull {
            it.optString("kid") == kid && it.optString("kty") == "RSA"
        } ?: error("找不到 ChatGPT 身份签名密钥")
        val modulus = BigInteger(1, unb64(key.getString("n")))
        val exponent = BigInteger(1, unb64(key.getString("e")))
        val publicKey = KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, exponent))
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initVerify(publicKey)
        signature.update("${parts[0]}.${parts[1]}".toByteArray())
        require(signature.verify(unb64(parts[2]))) { "ChatGPT 身份签名校验失败" }
        val claims = JSONObject(String(unb64(parts[1])))
        val now = System.currentTimeMillis() / 1000
        require(claims.optString("iss") == ISSUER && claims.optString("nonce") == nonce)
        require(claims.optLong("exp") > now - 5 && claims.optLong("iat") <= now + 5)
        val audience = claims.opt("aud")
        require(audience == clientId || (audience is org.json.JSONArray &&
            (0 until audience.length()).any { audience.optString(it) == clientId }))
        require(claims.optString("sub").isNotBlank())
        return claims
    }

    private fun postForm(url: String, params: Map<String, String>): JSONObject {
        val conn = URL(url).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
            conn.connectTimeout = 15_000
            conn.readTimeout = 30_000
            conn.outputStream.use { it.write(encodeForm(params).toByteArray()) }
            val body = (if (conn.responseCode in 200..299) conn.inputStream else conn.errorStream)
                ?.bufferedReader()?.use { it.readText() }.orEmpty()
            require(conn.responseCode in 200..299) { "ChatGPT 授权失败（HTTP ${conn.responseCode}）：${body.take(300)}" }
            return JSONObject(body)
        } finally { conn.disconnect() }
    }

    private fun getText(url: String): String {
        val conn = URL(url).openConnection() as HttpURLConnection
        try {
            conn.connectTimeout = 15_000
            conn.readTimeout = 20_000
            require(conn.responseCode in 200..299) { "读取 ChatGPT 公钥失败" }
            return conn.inputStream.bufferedReader().use { it.readText() }
        } finally { conn.disconnect() }
    }

    private fun encodeForm(map: Map<String, String>) = map.entries.joinToString("&") {
        "${URLEncoder.encode(it.key, "UTF-8")}=${URLEncoder.encode(it.value, "UTF-8")}" }
    private fun decodeQuery(query: String) = query.split('&').mapNotNull {
        val bits = it.split('=', limit = 2)
        if (bits.size == 2) URLDecoder.decode(bits[0], "UTF-8") to URLDecoder.decode(bits[1], "UTF-8") else null
    }.toMap()
    private fun randomUrlSafe(size: Int) = ByteArray(size).also { random.nextBytes(it) }.let(::b64)
    private fun b64(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    private fun unb64(text: String) = Base64.decode(text, Base64.URL_SAFE or Base64.NO_WRAP)
}
