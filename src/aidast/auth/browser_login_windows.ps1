param(
    [Parameter(Mandatory=$true)][string]$TargetUrl,
    [Parameter(Mandatory=$true)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
$target = [Uri]$TargetUrl
if ($target.Scheme -notin @('https', 'http') -or $target.UserInfo) { throw 'Invalid target URL' }
$targetOrigin = $target.GetLeftPart([UriPartial]::Authority).ToLowerInvariant()
$targetHost = $target.Host.ToLowerInvariant()
$chromePath = $null
foreach ($baseDir in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA)) {
    if ($baseDir) {
        $candidate = Join-Path $baseDir 'Google\Chrome\Application\chrome.exe'
        if (Test-Path -LiteralPath $candidate) { $chromePath = $candidate; break }
    }
}
if (-not $chromePath) { throw 'Google Chrome is not installed on Windows' }
$sessionDir = Split-Path -Parent $OutputPath
$profileDir = Join-Path $sessionDir 'chrome-profile'
$null = New-Item -ItemType Directory -Force -Path $profileDir
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
try {
    $listener.Start()
    $debugPort = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
} finally {
    $listener.Stop()
}
$chromeArgs = @("--remote-debugging-port=$debugPort", '--remote-debugging-address=127.0.0.1', "--user-data-dir=`"$profileDir`"",
    '--no-first-run', '--no-default-browser-check', '--no-proxy-server', "`"$TargetUrl`"")
$chromeProcess = $null
$script:socket = $null
$script:messageId = 0
$script:authenticationEndpoints = @{}
function ConvertTo-SafeAuthenticationPath([Uri]$RequestUri) {
    $sensitive = @('activate','activation','callback','confirm','invite','magic','magic-link','magic-login','reset','token','verify','verification')
    $segments = $RequestUri.AbsolutePath.Split('/')
    $safe = New-Object Collections.Generic.List[string]
    for ($index = 0; $index -lt $segments.Count; $index++) {
        $segment = $segments[$index]
        $decoded = [Uri]::UnescapeDataString($segment)
        $previous = if ($index -gt 0) { $segments[$index - 1].ToLowerInvariant() } else { '' }
        $dynamic = $segment -and (
            $sensitive -contains $previous -or
            $decoded -match '^\d+$' -or
            $decoded -match '^[0-9a-fA-F]{8,}$' -or
            $decoded -match '^[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}$' -or
            ($decoded.Length -ge 16 -and $decoded -match '^[A-Za-z0-9_+=.-]+$' -and
             $decoded -match '[A-Za-z]' -and $decoded -match '\d') -or
            $decoded -ne $segment
        )
        $safe.Add($(if ($dynamic) { ':secret' } else { $segment }))
    }
    return ($safe -join '/')
}
function Save-AuthenticationRequest($Parameters) {
    if (-not $Parameters -or -not $Parameters.request) { return }
    try { $requestUri = [Uri]$Parameters.request.url } catch { return }
    if ($requestUri.GetLeftPart([UriPartial]::Authority).ToLowerInvariant() -ne $targetOrigin) { return }
    $method = ([string]$Parameters.request.method).ToUpperInvariant()
    if (-not $method -or -not $requestUri.AbsolutePath.StartsWith('/')) { return }
    $path = ConvertTo-SafeAuthenticationPath $requestUri
    $key = "$method`n$targetOrigin`n$path"
    $script:authenticationEndpoints[$key] = @{
        method = $method
        origin = $targetOrigin
        path = $path
        source = 'auth_bootstrap'
    }
}
function Invoke-Cdp([string]$Method, [hashtable]$Parameters = @{}, [string]$SessionId = '') {
    $script:messageId++
    $id = $script:messageId
    $message = @{id=$id; method=$Method; params=$Parameters}
    if ($SessionId) { $message.sessionId = $SessionId }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($message | ConvertTo-Json -Depth 30 -Compress))
    $cancel = New-Object Threading.CancellationTokenSource
    $cancel.CancelAfter(15000)
    try {
        $segment = New-Object 'ArraySegment[byte]' -ArgumentList (,$bytes)
        $script:socket.SendAsync($segment, [Net.WebSockets.WebSocketMessageType]::Text, $true, $cancel.Token).GetAwaiter().GetResult()
        while ($true) {
            $buffer = New-Object byte[] 65536
            $stream = New-Object IO.MemoryStream
            try {
                do {
                    $chunk = $script:socket.ReceiveAsync([ArraySegment[byte]]::new($buffer), $cancel.Token).GetAwaiter().GetResult()
                    if ($chunk.MessageType -eq [Net.WebSockets.WebSocketMessageType]::Close) { throw 'Chrome closed the session export connection' }
                    $stream.Write($buffer, 0, $chunk.Count)
                    if ($stream.Length -gt 16777216) { throw 'Session export response exceeds limit' }
                } while (-not $chunk.EndOfMessage)
                $reply = [Text.Encoding]::UTF8.GetString($stream.ToArray()) | ConvertFrom-Json
            } finally { $stream.Dispose() }
            if ($reply.method -eq 'Network.requestWillBeSent') {
                Save-AuthenticationRequest $reply.params
                continue
            }
            if ($reply.id -eq $id) {
                if ($reply.error) { throw "Chrome session export command failed: $Method" }
                return $reply.result
            }
        }
    } finally { $cancel.Dispose() }
}
try {
    $chromeProcess = Start-Process -FilePath $chromePath -ArgumentList $chromeArgs -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    $version = $null
    while (-not $version) {
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Chrome export connection is unavailable' }
        try {
            $version = Invoke-RestMethod -Uri "http://127.0.0.1:$debugPort/json/version" -TimeoutSec 1
        } catch {
            Start-Sleep -Milliseconds 100
        }
    }
    $browserSocket = [Uri]$version.webSocketDebuggerUrl
    if ($browserSocket.Scheme -ne 'ws' -or $browserSocket.Host -ne '127.0.0.1' -or
        $browserSocket.Port -ne $debugPort -or -not $browserSocket.AbsolutePath.StartsWith('/devtools/browser/')) {
        throw 'Invalid Chrome export endpoint'
    }
    $script:socket = New-Object Net.WebSockets.ClientWebSocket
    $connectCancel = New-Object Threading.CancellationTokenSource
    $connectCancel.CancelAfter(15000)
    try {
        $script:socket.ConnectAsync($browserSocket, $connectCancel.Token).GetAwaiter().GetResult()
    } finally { $connectCancel.Dispose() }
    # Attach passive Network observers before operator interaction. No request
    # headers, post data, response bodies, routing, or proxying are enabled.
    foreach ($tab in (Invoke-Cdp 'Target.getTargets').targetInfos) {
        if ($tab.type -ne 'page') { continue }
        $networkSession = (Invoke-Cdp 'Target.attachToTarget' @{targetId=$tab.targetId; flatten=$true}).sessionId
        $null = Invoke-Cdp 'Network.enable' @{
            maxTotalBufferSize=0; maxResourceBufferSize=0; maxPostDataSize=0
        } $networkSession
    }
    Write-Host 'Log in using the Windows Chrome window. Keep the target page open when finished.'
    $null = Read-Host 'After completing login, press Enter to export the target session'
    $cookies = @()
    foreach ($cookie in (Invoke-Cdp 'Storage.getCookies').cookies) {
        $domain = $cookie.domain.ToLowerInvariant()
        $root = $domain.TrimStart('.')
        if ($targetHost -eq $root -or ($domain.StartsWith('.') -and $targetHost.EndsWith('.' + $root))) {
            $cookies += $cookie
        }
    }
    $origins = @()
    $sessionStorage = @{}
    $encodedOrigin = $targetOrigin | ConvertTo-Json -Compress
    $expression = "(() => { if (location.origin !== $encodedOrigin) return null; return {origin: location.origin, localStorage: Object.entries(localStorage).map(([name,value]) => ({name,value})), sessionStorage: Object.fromEntries(Object.entries(sessionStorage))}; })()"
    foreach ($tab in (Invoke-Cdp 'Target.getTargets').targetInfos) {
        if ($tab.type -ne 'page') { continue }
        try { $tabOrigin = ([Uri]$tab.url).GetLeftPart([UriPartial]::Authority).ToLowerInvariant() } catch { continue }
        if ($tabOrigin -ne $targetOrigin) { continue }
        $session = (Invoke-Cdp 'Target.attachToTarget' @{targetId=$tab.targetId; flatten=$true}).sessionId
        try {
            $evaluated = Invoke-Cdp 'Runtime.evaluate' @{expression=$expression; returnByValue=$true} $session
            if ($evaluated.exceptionDetails) { throw 'Could not export target browser storage' }
            $value = $evaluated.result.value
            if ($value -and $value.origin -eq $targetOrigin) {
                $origins = @(@{origin=$targetOrigin; localStorage=@($value.localStorage)})
                $sessionStorage[$targetOrigin] = $value.sessionStorage
            }
        } finally { $null = Invoke-Cdp 'Target.detachFromTarget' @{sessionId=$session} }
    }
    if ($origins.Count -eq 0) { throw 'Finish login and return to the target origin before exporting' }
    $document = @{
        cookies=$cookies
        origins=$origins
        session_storage=$sessionStorage
        authentication_endpoints=@($script:authenticationEndpoints.Values)
    }
    [IO.File]::WriteAllText($OutputPath, ($document | ConvertTo-Json -Depth 50), [Text.UTF8Encoding]::new($false))
    Write-Host 'Target session exported. Returning to AI-DAST.'
} finally {
    if ($script:socket) {
        try { $null = Invoke-Cdp 'Browser.close' } catch { }
        $script:socket.Dispose()
    }
    if ($chromeProcess -and -not $chromeProcess.HasExited) {
        if (-not $chromeProcess.WaitForExit(5000)) { $chromeProcess.Kill() }
    }
}
