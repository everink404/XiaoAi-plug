package io.mo.xiaoaiplug.config

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** Responses calls execute only in the module process. The Xposed host never receives OAuth tokens. */
object ChatGptPlanClient {
    fun listModels(context: Context): List<String> {
        val conn = URL("https://api.openai.com/v1/models").openConnection() as HttpURLConnection
        try {
            conn.setRequestProperty("Authorization", "Bearer ${ChatGptPlanAuth.accessToken(context)}")
            conn.connectTimeout = 15_000
            conn.readTimeout = 20_000
            val json = JSONObject(readResponse(conn))
            val models = json.optJSONArray("models") ?: json.optJSONArray("data") ?: JSONArray()
            return (0 until models.length()).mapNotNull { index ->
                val item = models.optJSONObject(index) ?: return@mapNotNull null
                if (item.has("visibility") && item.optString("visibility") != "list") return@mapNotNull null
                item.optString("slug").ifBlank { item.optString("id") }.takeIf { it.isNotBlank() }
            }.distinct()
        } finally { conn.disconnect() }
    }

    fun respond(context: Context, model: String, messages: JSONArray): String {
        val input = JSONArray()
        val instructions = StringBuilder()
        for (i in 0 until messages.length()) {
            val message = messages.getJSONObject(i)
            val role = message.optString("role")
            val content = message.optString("content")
            if (role == "system") instructions.append(content).append("\n\n")
            else if (role == "user" || role == "assistant") {
                input.put(JSONObject().put("role", role).put("content", content))
            }
        }
        val body = JSONObject().put("model", model).put("input", input)
            .put("instructions", instructions.toString().trim())
            .put("store", false).put("stream", true)
        val conn = URL("https://api.openai.com/v1/responses").openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setRequestProperty("Authorization", "Bearer ${ChatGptPlanAuth.accessToken(context)}")
            conn.setRequestProperty("Content-Type", "application/json")
            conn.connectTimeout = 15_000
            conn.readTimeout = 60_000
            conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            if (conn.responseCode !in 200..299) throw IllegalStateException("ChatGPT 请求失败（HTTP ${conn.responseCode}）：${readResponse(conn).take(300)}")
            val text = StringBuilder()
            var completed = false
            conn.inputStream.bufferedReader().use { reader ->
                while (true) {
                    val line = reader.readLine() ?: break
                    if (!line.startsWith("data:")) continue
                    val payload = line.substring(5).trim()
                    if (payload.isEmpty() || payload == "[DONE]") continue
                    val event = JSONObject(payload)
                    when (event.optString("type")) {
                        "response.output_text.delta" -> text.append(event.optString("delta"))
                        "response.completed" -> {
                            completed = true
                            if (text.isEmpty()) {
                                val output = event.optJSONObject("response")?.optJSONArray("output")
                                if (output != null) for (i in 0 until output.length()) {
                                    val parts = output.optJSONObject(i)?.optJSONArray("content") ?: continue
                                    for (j in 0 until parts.length()) text.append(parts.optJSONObject(j)?.optString("text").orEmpty())
                                }
                            }
                        }
                        "response.failed", "response.incomplete" ->
                            error("ChatGPT 未完成回复：${event.optJSONObject("response")?.optJSONObject("error")?.optString("code").orEmpty()}")
                    }
                }
            }
            check(completed && text.isNotBlank()) { "ChatGPT 回复中断或为空" }
            return text.toString()
        } finally { conn.disconnect() }
    }

    private fun readResponse(conn: HttpURLConnection): String =
        (if (conn.responseCode in 200..299) conn.inputStream else conn.errorStream)
            ?.bufferedReader()?.use { it.readText() }.orEmpty().also {
                check(conn.responseCode in 200..299) { "ChatGPT 请求失败（HTTP ${conn.responseCode}）：${it.take(300)}" }
            }
}
