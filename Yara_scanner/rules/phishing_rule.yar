rule PhishingSample
{
    meta:
        description = "Detects files containing phishing keywords and suspicious URLs"
        author = "Mounika"
        date = "2025-08-14"

    strings:
        // Common phishing words
        $keyword1 = "login" nocase
        $keyword2 = "verify your account" nocase
        $keyword3 = "update your password" nocase

        // Simple regex for suspicious URLs
        $url = /https?:\/\/[a-z0-9\-]+\.[a-z]{2,}(\/\S*)?/ nocase

    condition:
        any of ($keyword*) and $url
}
