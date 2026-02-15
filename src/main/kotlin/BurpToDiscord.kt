import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.StatusCodeClass
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.audit.AuditIssueHandler
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.ui.settings.SettingsPanelBuilder
import burp.api.montoya.ui.settings.SettingsPanelPersistence
import burp.api.montoya.ui.settings.SettingsPanelSetting
import burp.api.montoya.ui.settings.SettingsPanelWithData
import com.vladsch.flexmark.ext.tables.TablesExtension
import com.vladsch.flexmark.html2md.converter.FlexmarkHtmlConverter
import com.vladsch.flexmark.parser.Parser
import com.vladsch.flexmark.util.data.MutableDataSet
import org.json.JSONArray
import org.json.JSONObject

class BurpToDiscord : BurpExtension {
    companion object {
        var unloaded = false
        lateinit var montoyaApi: MontoyaApi
        lateinit var settings: SettingsPanelWithData
    }

    override fun initialize(api: MontoyaApi?) {
        if (api == null) {
            return
        }
        montoyaApi = api

        val name = "burp-to-discord"
        api.extension().setName(name)
        api.logging().logToOutput("Loaded $name")

        api.scanner().registerAuditIssueHandler(MyAuditIssueHandler())

        // Create settings panel
        settings =
            SettingsPanelBuilder.settingsPanel()
                .withPersistence(SettingsPanelPersistence.PROJECT_SETTINGS)
                .withTitle("burp-to-discord")
                .withDescription(
                    """
                    Settings for burp-to-discord extension: 

                    To grab your webhook url:
                    1) Right-click your chosen discord channel
                    2) Select "Edit Channel"
                    3) Select "Integrations" -> "Webhooks"
                    4) Create a new webhook and copy the URL

                    To grab discord user ID (this will @ you in discord):
                    1) Under "Advanced" settings, enable "Developer Mode"
                    2) Under "My Account" select "..." next to your username and then select "Copy User ID"
                    
                    """.trimIndent(),
                )
                .withKeywords("Discord", "burp-to-discord", "Notifications")
                .withSettings(
                    SettingsPanelSetting.stringSetting(
                        "Discord Webhook URL",
                        "https://discord.com/api/webhooks/<your-webhook-id>",
                    ),
                )
                .withSettings(
                    SettingsPanelSetting.stringSetting("Optional: Discord User ID", "000000000000000000"),
                )
                .withSettings(
                    SettingsPanelSetting.booleanSetting("@Discord User ID", true),
                )
                .withSettings(
                    SettingsPanelSetting.booleanSetting("Include request/response data", true),
                )
                .build()

        api.userInterface().registerSettingsPanel(settings)

        // Register unloading handler
        api.extension().registerUnloadingHandler {
            unloaded = true
            api.logging().logToOutput("Unloading Extension...")
        }
    }

    private class MyAuditIssueHandler : AuditIssueHandler {
        override fun handleNewAuditIssue(issue: AuditIssue?) {
            montoyaApi.logging().logToOutput("New Issue Reported!!!")

            if (settings.getString("Discord Webhook URL") ==
                "https://discord.com/api/webhooks/<your-webhook-id>"
            ) {
                montoyaApi.logging().logToOutput("You need to set your discord webhook URL for this to work!")
                return
            }

            val issueName = issue?.name()
            // Prevent discord from parsing the URL as a URL
            val url = issue?.baseUrl().toString().replace("/", "\\/")
            val options = MutableDataSet()
            options.set(Parser.EXTENSIONS, listOf(TablesExtension.create()))
            val converter = FlexmarkHtmlConverter.builder(options).build()
            val details = converter.convert(issue?.detail().toString()).trimEnd().replace("\n", "\n> ")
            val requestResponses = issue?.requestResponses()
            val attachmentsList = JSONArray()

            if (requestResponses == null) {
                montoyaApi.logging().logToError("Reported issue had no attached requestResponse... Skipping")
                return
            }

            if (settings.getBoolean("Include request/response data")) {
                for (requestResponse in requestResponses) {
                    var req = requestResponse.request().toString()

                    var resp = ""

                    if (requestResponse.hasResponse()) {
                        resp = requestResponse.response().toString()
                    }

                    if (req.length > 2000) {
                        req = req.substring(0, 2000)
                    }
                    if (resp.length > 2000) {
                        resp = resp.substring(0, 2000)
                    }

                    val attachment = JSONObject()
                    attachment.put(
                        "description",
                        "\r\nRequest #${requestResponses.indexOf(requestResponse) + 1}:\r\n```http\r\n$req\r\n```\r\nResponse #${requestResponses.indexOf(requestResponse) + 1}:\r\n```http\r\n$resp\r\n```\r\n".trimIndent(),
                    )
                    attachmentsList.put(attachment)
                }
            }

            // Optionally include a User ID to @ a user

            val content: String

            val discordUserID = settings.getString("Optional: Discord User ID")

            if (settings.getBoolean("@Discord User ID") && discordUserID != "000000000000000000") {
                content =
                    """
                    > <@$discordUserID>, new issue!
                    > **Title**: $issueName
                    > **URL**: $url
                    > **Details**: $details
                    """.trimIndent()
            } else {
                content =
                    """
                    > New issue!
                    > **Title**: $issueName
                    > **URL**: $url
                    > **Details**: $details
                    """.trimIndent()
            }

            val jsonContent = JSONObject()
            jsonContent.put("content", content)

            val discordRequest =
                HttpRequest.httpRequestFromUrl(settings.getString("Discord Webhook URL"))
                    .withMethod("POST")
                    .withHeader("Content-Type", "application/json")
                    .withBody(jsonContent.toString())

            val requestResponse = montoyaApi.http().sendRequest(discordRequest)

            if (!requestResponse.response().isStatusCodeClass(StatusCodeClass.CLASS_2XX_SUCCESS)) {
                montoyaApi.logging().logToError(
                    "Error when sending issue to discord: ${requestResponse.response().statusCode()} | ${requestResponse.response().bodyToString()}",
                )
            }

            // This will only do something if there is actually an entry in attachmentsList
            for (attachment in attachmentsList) {
                val attachmentJsonContent = JSONObject()
                val smallArray = JSONArray()
                smallArray.put(attachment)

                attachmentJsonContent.put("embeds", smallArray)

                val discordAttachmentRequest =
                    HttpRequest.httpRequestFromUrl(
                        settings.getString("Discord Webhook URL"),
                    )
                        .withMethod("POST")
                        .withHeader("Content-Type", "application/json")
                        .withBody(attachmentJsonContent.toString())
                val requestResponseAttachments = montoyaApi.http().sendRequest(discordAttachmentRequest)

                if (!requestResponseAttachments.response().isStatusCodeClass(StatusCodeClass.CLASS_2XX_SUCCESS)) {
                    montoyaApi.logging().logToError(
                        "Error when sending attachments to discord: " +
                            "${requestResponseAttachments.response().statusCode()} | " +
                            requestResponseAttachments.response().bodyToString(),
                    )
                }
            }
        }
    }
}
