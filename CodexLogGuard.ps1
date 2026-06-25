param(
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom

$script:RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:LogDir = Join-Path $script:RootDir "monitor-logs"
$script:CodexDir = Join-Path $env:USERPROFILE ".codex"
$script:LogDbPath = Join-Path $script:CodexDir "logs_2.sqlite"
$script:BackupDir = Join-Path $script:CodexDir "logs_backup"
$script:CurrentCsvPath = ""
$script:IsMonitoring = $false
$script:BlockerInstalled = $false
$script:CountingEnabled = $true
$script:CountingActiveThisRun = $false
$script:MonitorHadBlockerAtStart = $false
$script:MonitorStartCounter = 0
$script:MonitorPreviousCounter = 0
$script:MonitorWarnMBps = 0.5
$script:MonitorActiveWindowSeconds = 120
$script:EvaluationSamples = @()
$script:SampleIndex = 0
$script:InstanceMutexName = "codex_write_disk_abnormal_detector"
$script:InstanceMutex = $null
$script:InstanceDir = Join-Path $env:TEMP "codex写盘异常检测"
$script:RestartCloseRequested = $false
$script:RestartPromptActive = $false

function Submit-RestartRequestToExistingInstance([System.Threading.Mutex]$Mutex) {
    if (-not (Test-Path -LiteralPath $script:InstanceDir)) {
        New-Item -ItemType Directory -Path $script:InstanceDir -Force | Out-Null
    }

    $requestId = [guid]::NewGuid().ToString("N")
    $requestPath = Join-Path $script:InstanceDir "restart-request-$requestId.txt"
    $responsePath = Join-Path $script:InstanceDir "restart-response-$requestId.txt"
    [System.IO.File]::WriteAllText($requestPath, $requestId, (New-Object System.Text.UTF8Encoding($false)))

    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $responsePath) {
            $response = [System.IO.File]::ReadAllText($responsePath).Trim()
            Remove-Item -LiteralPath $responsePath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $requestPath -Force -ErrorAction SilentlyContinue
            if ($response -ne "accepted") {
                return $false
            }

            $mutexDeadline = (Get-Date).AddSeconds(60)
            while ((Get-Date) -lt $mutexDeadline) {
                if ($Mutex.WaitOne(500, $false)) {
                    return $true
                }
            }
            return $false
        }
        Start-Sleep -Milliseconds 500
    }

    Remove-Item -LiteralPath $requestPath -Force -ErrorAction SilentlyContinue
    return $false
}

function Initialize-SingleInstance {
    if (-not (Test-Path -LiteralPath $script:InstanceDir)) {
        New-Item -ItemType Directory -Path $script:InstanceDir -Force | Out-Null
    }

    $mutex = New-Object System.Threading.Mutex($false, $script:InstanceMutexName)
    if ($mutex.WaitOne(0, $false)) {
        $script:InstanceMutex = $mutex
        Get-ChildItem -LiteralPath $script:InstanceDir -Filter "restart-*.txt" -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
        return
    }

    if (Submit-RestartRequestToExistingInstance $mutex) {
        $script:InstanceMutex = $mutex
        return
    }

    $mutex.Dispose()
    exit 0
}

if (-not $SelfTest) {
    Initialize-SingleInstance
}

function Get-PythonCommand {
    if (Get-Command python -ErrorAction SilentlyContinue) {
        return "python"
    }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        return "py -3"
    }
    return ""
}

function Invoke-PythonText([string]$Script, [hashtable]$Env = @{}) {
    $pythonCommand = Get-PythonCommand
    if (-not $pythonCommand) {
        throw "未找到 Python，无法读取或修改 SQLite。"
    }

    foreach ($key in $Env.Keys) {
        [Environment]::SetEnvironmentVariable($key, [string]$Env[$key], "Process")
    }

    $cleanScript = $Script.TrimStart([char]0xFEFF)
    if ($pythonCommand -eq "python") {
        return $cleanScript | python
    }
    return $cleanScript | py -3
}

function Invoke-PythonJson([string]$Script, [hashtable]$Env = @{}) {
    $encoded = Invoke-PythonText $Script $Env
    $encodedText = (($encoded | Select-Object -First 1) -as [string]).Trim()
    if (-not $encodedText) {
        throw "Python 没有返回数据。"
    }
    $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedText))
    return $json | ConvertFrom-Json
}

function ConvertTo-ShortText([string]$Value, [int]$MaxLength = 80) {
    if (-not $Value) {
        return ""
    }
    $clean = ($Value -replace "[\r\n\t]+", " ").Trim()
    if ($clean.Length -le $MaxLength) {
        return $clean
    }
    return $clean.Substring(0, $MaxLength) + "..."
}

function Get-FileMB([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return 0
    }
    $item = Get-Item -LiteralPath $Path -Force
    return [math]::Round($item.Length / 1MB, 3)
}

function Get-DirectoryMB([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return 0
    }
    $sum = (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum
    if ($null -eq $sum) {
        return 0
    }
    return [math]::Round($sum / 1MB, 3)
}

function Get-CodexProcesses {
    return @(Get-Process -Name "Codex", "codex" -ErrorAction SilentlyContinue)
}

function Get-LogGuardStatus {
    $script = @'
import base64
import json
import os
import sqlite3

db_path = os.environ["CODEX_LOG_DB"]
result = {
    "database": db_path,
    "db_exists": os.path.exists(db_path),
    "logs_count": None,
    "logs_min_id": None,
    "logs_max_id": None,
    "trigger_installed": False,
    "blocker_mode": "数据库不存在",
    "trigger_name": "",
    "trigger_table": "",
    "counter_total": None,
    "last_session_start_count": None,
    "last_session_delta": None,
    "error": "",
}

try:
    if result["db_exists"]:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
        has_logs = cur.fetchone() is not None
        if has_logs:
            cur.execute("SELECT COUNT(*), MIN(id), MAX(id) FROM logs")
            count, min_id, max_id = cur.fetchone()
            result["logs_count"] = count
            result["logs_min_id"] = min_id
            result["logs_max_id"] = max_id

        cur.execute("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='trigger' AND name='block_log_inserts'")
        row = cur.fetchone()
        if row:
            result["trigger_installed"] = True
            result["trigger_name"] = row[0]
            result["trigger_table"] = row[1]
            sql = row[2] or ""
            if "codex_log_blocker_counter" in sql or "blocked_count" in sql:
                result["blocker_mode"] = "计数拦截器"
            else:
                result["blocker_mode"] = "纯拦截器"
        else:
            result["blocker_mode"] = "未安装"

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='codex_log_blocker_counter'")
        if cur.fetchone() is not None:
            cur.execute("PRAGMA table_info(codex_log_blocker_counter)")
            columns = {row[1] for row in cur.fetchall()}
            if "last_session_start_count" in columns:
                cur.execute("SELECT blocked_count, last_session_start_count FROM codex_log_blocker_counter WHERE id = 1")
                counter_row = cur.fetchone()
                if counter_row:
                    result["counter_total"] = counter_row[0]
                    result["last_session_start_count"] = counter_row[1]
                    result["last_session_delta"] = counter_row[0] - counter_row[1]
            else:
                cur.execute("SELECT blocked_count FROM codex_log_blocker_counter WHERE id = 1")
                counter_row = cur.fetchone()
                if counter_row:
                    result["counter_total"] = counter_row[0]
                    result["last_session_start_count"] = 0
                    result["last_session_delta"] = counter_row[0]
        con.close()
except Exception as exc:
    result["error"] = str(exc)

payload = json.dumps(result, ensure_ascii=False).encode("utf-8")
print(base64.b64encode(payload).decode("ascii"))
'@
    $status = Invoke-PythonJson $script @{ CODEX_LOG_DB = $script:LogDbPath }
    $status | Add-Member -NotePropertyName DbMB -NotePropertyValue (Get-FileMB $script:LogDbPath) -Force
    $status | Add-Member -NotePropertyName WalMB -NotePropertyValue (Get-FileMB ($script:LogDbPath + "-wal")) -Force
    $status | Add-Member -NotePropertyName ShmMB -NotePropertyValue (Get-FileMB ($script:LogDbPath + "-shm")) -Force
    $status | Add-Member -NotePropertyName BackupDirMB -NotePropertyValue (Get-DirectoryMB $script:BackupDir) -Force
    return $status
}

function Invoke-LogBlockerAction([string]$Action) {
    $script = @'
import os
import sqlite3

db_path = os.environ["CODEX_LOG_DB"]
action = os.environ["CODEX_LOG_ACTION"]

pure_trigger_sql = """
CREATE TRIGGER IF NOT EXISTS block_log_inserts
BEFORE INSERT ON logs
BEGIN
    SELECT RAISE(IGNORE);
END;
"""

con = sqlite3.connect(db_path, timeout=10)
cur = con.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
if cur.fetchone() is None:
    raise SystemExit("logs table missing")

if action == "install" or action == "restore":
    cur.execute("DROP TRIGGER IF EXISTS block_log_inserts")
    cur.execute(pure_trigger_sql)
elif action == "remove":
    cur.execute("DROP TRIGGER IF EXISTS block_log_inserts")
else:
    raise SystemExit(f"unknown action: {action}")

con.commit()
con.close()
print("ok")
'@
    Invoke-PythonText $script @{ CODEX_LOG_DB = $script:LogDbPath; CODEX_LOG_ACTION = $Action } | Out-Null
}

function Invoke-LogCounterAction([string]$Action) {
    $script = @'
import os
import sqlite3

db_path = os.environ["CODEX_LOG_DB"]
action = os.environ["CODEX_COUNTER_ACTION"]

pure_trigger_sql = """
CREATE TRIGGER IF NOT EXISTS block_log_inserts
BEFORE INSERT ON logs
BEGIN
    SELECT RAISE(IGNORE);
END;
"""

counter_table_sql = """
CREATE TABLE IF NOT EXISTS codex_log_blocker_counter (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    blocked_count INTEGER NOT NULL DEFAULT 0,
    last_session_start_count INTEGER NOT NULL DEFAULT 0,
    enabled_at TEXT,
    updated_at TEXT
);
"""

counter_trigger_sql = """
CREATE TRIGGER IF NOT EXISTS block_log_inserts
BEFORE INSERT ON logs
BEGIN
    UPDATE codex_log_blocker_counter
    SET blocked_count = blocked_count + 1,
        updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now')
    WHERE id = 1;
    SELECT RAISE(IGNORE);
END;
"""

con = sqlite3.connect(db_path, timeout=10)
cur = con.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
has_logs = cur.fetchone() is not None
if not has_logs and action == "reset":
    print(0)
    con.close()
    raise SystemExit(0)
if not has_logs:
    raise SystemExit("logs table missing")

if action == "enable":
    cur.execute(counter_table_sql)
    cur.execute("PRAGMA table_info(codex_log_blocker_counter)")
    columns = {row[1] for row in cur.fetchall()}
    if "last_session_start_count" not in columns:
        cur.execute("ALTER TABLE codex_log_blocker_counter ADD COLUMN last_session_start_count INTEGER NOT NULL DEFAULT 0")
    cur.execute(
        """
        INSERT INTO codex_log_blocker_counter (id, blocked_count, last_session_start_count, enabled_at, updated_at)
        VALUES (1, 0, 0, strftime('%Y-%m-%d %H:%M:%f', 'now'), strftime('%Y-%m-%d %H:%M:%f', 'now'))
        ON CONFLICT(id) DO UPDATE SET
            last_session_start_count = blocked_count,
            enabled_at = excluded.enabled_at,
            updated_at = excluded.updated_at
        """
    )
    cur.execute("DROP TRIGGER IF EXISTS block_log_inserts")
    cur.execute(counter_trigger_sql)
    con.commit()
elif action == "restore":
    cur.execute("DROP TRIGGER IF EXISTS block_log_inserts")
    cur.execute(pure_trigger_sql)
    con.commit()
elif action == "reset":
    cur.execute(counter_table_sql)
    cur.execute("PRAGMA table_info(codex_log_blocker_counter)")
    columns = {row[1] for row in cur.fetchall()}
    if "last_session_start_count" not in columns:
        cur.execute("ALTER TABLE codex_log_blocker_counter ADD COLUMN last_session_start_count INTEGER NOT NULL DEFAULT 0")
    cur.execute(
        """
        INSERT INTO codex_log_blocker_counter (id, blocked_count, last_session_start_count, enabled_at, updated_at)
        VALUES (1, 0, 0, NULL, strftime('%Y-%m-%d %H:%M:%f', 'now'))
        ON CONFLICT(id) DO UPDATE SET
            blocked_count = 0,
            last_session_start_count = 0,
            updated_at = excluded.updated_at
        """
    )
    con.commit()
elif action == "read":
    pass
else:
    raise SystemExit(f"unknown action: {action}")

cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='codex_log_blocker_counter'")
if cur.fetchone() is None:
    print(0)
    con.close()
    raise SystemExit(0)

cur.execute("SELECT blocked_count FROM codex_log_blocker_counter WHERE id = 1")
row = cur.fetchone()
print(0 if row is None else int(row[0]))
con.close()
'@
    $result = Invoke-PythonText $script @{ CODEX_LOG_DB = $script:LogDbPath; CODEX_COUNTER_ACTION = $Action }
    return [int](($result | Select-Object -Last 1) -as [string])
}

function Assert-BackupDirIsSafe {
    if (-not (Test-Path -LiteralPath $script:CodexDir)) {
        throw "没有找到 .codex 目录：$script:CodexDir"
    }

    $codexFullPath = [System.IO.Path]::GetFullPath($script:CodexDir)
    $backupFullPath = [System.IO.Path]::GetFullPath($script:BackupDir)
    if (-not $backupFullPath.StartsWith($codexFullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "暂存目录不在 .codex 目录内，已停止清理：$script:BackupDir"
    }
}

function Clear-BackupHistory {
    Assert-BackupDirIsSafe

    if (-not (Test-Path -LiteralPath $script:BackupDir)) {
        New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null
        return "暂存目录已创建；没有历史文件需要清空：$script:BackupDir"
    }

    $items = @(Get-ChildItem -LiteralPath $script:BackupDir -Force -ErrorAction SilentlyContinue)
    foreach ($item in $items) {
        Remove-Item -LiteralPath $item.FullName -Recurse -Force
    }

    if ($items.Count -eq 0) {
        return "暂存目录为空，没有历史文件需要清空：$script:BackupDir"
    }

    return "已清空历史暂存文件：$script:BackupDir"
}

function Backup-And-ClearLogs {
    $processes = Get-CodexProcesses
    if ($processes.Count -gt 0) {
        throw "检测到 Codex 仍在运行。请先完全退出 Codex，再清理文件。"
    }

    Assert-BackupDirIsSafe

    $files = @()
    foreach ($name in @("logs_2.sqlite", "logs_2.sqlite-wal", "logs_2.sqlite-shm")) {
        $path = Join-Path $script:CodexDir $name
        if (Test-Path -LiteralPath $path) {
            $files += Get-Item -LiteralPath $path -Force
        }
    }

    Clear-BackupHistory | Out-Null

    if ($files.Count -eq 0) {
        return "已清空暂存目录；没有找到 logs_2.sqlite 日志文件，无需移动。"
    }

    foreach ($file in $files) {
        Move-Item -LiteralPath $file.FullName -Destination $script:BackupDir
    }
    return "日志已移动到暂存目录：$script:BackupDir"
}

function Get-CodexProcessWriteStats {
    $rows = @(Get-CimInstance Win32_PerfFormattedData_PerfProc_Process |
        Where-Object { $_.Name -like "Codex*" -or $_.Name -like "codex*" })

    if ($rows.Count -eq 0) {
        return [pscustomobject]@{
            TotalWriteMBps = 0
            TopProcess = ""
            TopPID = ""
            TopWriteMBps = 0
            ProcessCount = 0
            Status = "未发现 Codex 进程"
        }
    }

    $sum = ($rows | Measure-Object -Property IOWriteBytesPersec -Sum).Sum
    $top = $rows | Sort-Object IOWriteBytesPersec -Descending | Select-Object -First 1
    $total = [math]::Round($sum / 1MB, 2)
    return [pscustomobject]@{
        TotalWriteMBps = $total
        TopProcess = $top.Name
        TopPID = $top.IDProcess
        TopWriteMBps = [math]::Round($top.IOWriteBytesPersec / 1MB, 2)
        ProcessCount = $rows.Count
        Status = if ($total -ge $script:MonitorWarnMBps) { "写盘偏高" } else { "正常" }
    }
}

function Get-RecentThreadContext {
    $stateDb = Join-Path $script:CodexDir "state_5.sqlite"
    if (-not (Test-Path -LiteralPath $stateDb)) {
        return [pscustomobject]@{
            TaskState = "未找到会话状态库"
            ThreadId = ""
            ThreadTitle = ""
            ThreadCwd = ""
            ThreadUpdatedAt = ""
            ThreadAgeSeconds = ""
            ThreadTitleSource = ""
        }
    }

    $script = @'
import base64
from datetime import datetime
import json
import os
import sqlite3
import time

path = os.environ["CODEX_STATE_DB"]
session_index_path = os.path.join(os.path.dirname(path), "session_index.jsonl")

def emit(payload):
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    print(base64.b64encode(raw).decode("ascii"))

def parse_index_time(value):
    if not value:
        return 0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0

def latest_index_title(thread_id, fallback_title):
    if not thread_id or not os.path.exists(session_index_path):
        return fallback_title or "", False
    latest_title = fallback_title or ""
    latest_ts = 0
    try:
        with open(session_index_path, "r", encoding="utf-8-sig") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except Exception:
                    continue
                if item.get("id") != thread_id:
                    continue
                ts = parse_index_time(item.get("updated_at", ""))
                if ts >= latest_ts:
                    latest_ts = ts
                    latest_title = item.get("thread_name") or latest_title
    except Exception:
        return fallback_title or "", False
    return latest_title, latest_ts > 0

try:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=1)
    cur = con.cursor()
    row = cur.execute(
        """
        SELECT id, title, cwd, updated_at_ms, updated_at, recency_at_ms, recency_at
        FROM threads
        ORDER BY COALESCE(updated_at_ms, recency_at_ms, updated_at * 1000, recency_at * 1000, 0) DESC
        LIMIT 1
        """
    ).fetchone()
    con.close()
    if not row:
        emit({})
    else:
        thread_id, title, cwd, updated_at_ms, updated_at, recency_at_ms, recency_at = row
        title, title_from_index = latest_index_title(thread_id, title)
        updated_ms = updated_at_ms or (updated_at * 1000 if updated_at else None) or recency_at_ms or (recency_at * 1000 if recency_at else None)
        age = None
        updated_iso = ""
        if updated_ms:
            now_ms = int(time.time() * 1000)
            age = max(0, int((now_ms - int(updated_ms)) / 1000))
            updated_iso = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(updated_ms) / 1000))
        emit({
            "thread_id": thread_id or "",
            "title": title or "",
            "title_source": "session_index" if title_from_index else "state_db",
            "cwd": cwd or "",
            "updated_at": updated_iso,
            "age_seconds": age,
        })
except Exception as exc:
    emit({"error": str(exc)})
'@

    try {
        $data = Invoke-PythonJson $script @{ CODEX_STATE_DB = $stateDb }
        $age = $data.age_seconds
        $taskState = if ($null -ne $age -and $age -le $script:MonitorActiveWindowSeconds) {
            "最近有会话活动"
        } else {
            "未检测到近期会话活动"
        }
        return [pscustomobject]@{
            TaskState = $taskState
            ThreadId = $data.thread_id
            ThreadTitle = ConvertTo-ShortText $data.title 80
            ThreadCwd = (($data.cwd -as [string]) -replace "^\\\\\?\\", "")
            ThreadUpdatedAt = $data.updated_at
            ThreadAgeSeconds = if ($null -eq $age) { "" } else { [int]$age }
            ThreadTitleSource = $data.title_source
        }
    } catch {
        return [pscustomobject]@{
            TaskState = "读取会话状态失败"
            ThreadId = ""
            ThreadTitle = ""
            ThreadCwd = ""
            ThreadUpdatedAt = ""
            ThreadAgeSeconds = ""
            ThreadTitleSource = ""
        }
    }
}

function Write-MonitorCsvRow([pscustomobject]$Sample) {
    if (-not $script:CurrentCsvPath) {
        return
    }

    $exists = Test-Path -LiteralPath $script:CurrentCsvPath
    if ($exists) {
        $Sample | Export-Csv -LiteralPath $script:CurrentCsvPath -NoTypeInformation -Append -Encoding UTF8
    } else {
        $Sample | Export-Csv -LiteralPath $script:CurrentCsvPath -NoTypeInformation -Encoding UTF8
    }
}

function New-MonitorSample {
    $stats = Get-CodexProcessWriteStats
    $thread = Get-RecentThreadContext
    $currentCounter = Invoke-LogCounterAction "read"
    if ($script:CountingActiveThisRun) {
        $sinceStart = $currentCounter - $script:MonitorStartCounter
        $sinceLast = $currentCounter - $script:MonitorPreviousCounter
        $script:MonitorPreviousCounter = $currentCounter
        $countMode = "监测期间计数"
    } else {
        $sinceStart = 0
        $sinceLast = 0
        $countMode = "未开启统计"
    }

    $taskState = $thread.TaskState
    if ($stats.Status -eq "写盘偏高" -and $taskState -eq "未检测到近期会话活动") {
        $taskState = "有写盘，但未匹配到近期会话"
    }
    $sampleStatus = $stats.Status
    if ($sinceLast -gt 0) {
        $sampleStatus = "已拦截"
    }

    return [pscustomobject]@{
        Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TotalWriteMBps = $stats.TotalWriteMBps
        TopProcess = $stats.TopProcess
        TopPID = $stats.TopPID
        TopWriteMBps = $stats.TopWriteMBps
        ProcessCount = $stats.ProcessCount
        Status = $sampleStatus
        TaskState = $taskState
        ActiveThreadId = $thread.ThreadId
        ActiveThreadTitle = $thread.ThreadTitle
        ActiveThreadCwd = $thread.ThreadCwd
        ActiveThreadUpdatedAt = $thread.ThreadUpdatedAt
        ActiveThreadAgeSeconds = $thread.ThreadAgeSeconds
        ActiveThreadTitleSource = $thread.ThreadTitleSource
        BlockedLogCountMode = $countMode
        BlockedLogInsertsTotal = $currentCounter
        BlockedLogInsertsSinceStart = $sinceStart
        BlockedLogInsertsSinceLastSample = $sinceLast
    }
}

function Get-DisplayBlockerStatus($Status) {
    if (-not $Status -or -not $Status.trigger_installed) {
        return "拦截器：未安装"
    }
    return "拦截器：拦截保护中"
}

function Update-CountingButtonText {
    if ($script:CountingEnabled) {
        $btnRestore.Text = "监测时计数"
        $btnRestore.ForeColor = $script:ColorSuccessText
    } else {
        $btnRestore.Text = "监测时不计数"
        $btnRestore.ForeColor = $script:ColorDangerText
    }
}

function Update-BlockerToggleButtonText {
    if ($script:BlockerInstalled) {
        $btnBlockerToggle.Text = "拦截保护中"
        $btnBlockerToggle.ForeColor = $script:ColorSuccessText
    } else {
        $btnBlockerToggle.Text = "拦截器未安装"
        $btnBlockerToggle.ForeColor = $script:ColorDangerText
    }
}

function Get-WriteEvaluation([object[]]$Samples) {
    if (-not $Samples -or $Samples.Count -eq 0) {
        return [pscustomobject]@{
            Level = "未检测"
            Text = "写盘评估：未检测"
            Detail = "开始监测后生成结论"
            Color = $script:ColorNeutralBg
        }
    }

    $ordered = @($Samples | Sort-Object Time)
    $latest = $ordered[-1]
    $windowStart60 = $latest.Time.AddSeconds(-60)
    $windowStart120 = $latest.Time.AddSeconds(-120)
    $last60 = @($ordered | Where-Object { $_.Time -ge $windowStart60 })
    $last120 = @($ordered | Where-Object { $_.Time -ge $windowStart120 })

    if ($last120.Count -lt 6) {
        return [pscustomobject]@{
            Level = "观察中"
            Text = "写盘评估：观察中"
            Detail = "样本不足 30 秒"
            Color = $script:ColorWarningBg
        }
    }

    $avg60 = if ($last60.Count -gt 0) { [math]::Round((($last60 | Measure-Object TotalWriteMBps -Average).Average), 3) } else { 0 }
    $avg120 = [math]::Round((($last120 | Measure-Object TotalWriteMBps -Average).Average), 3)
    $max120 = [math]::Round((($last120 | Measure-Object TotalWriteMBps -Maximum).Maximum), 3)
    $recent3 = @($ordered | Select-Object -Last 3)
    $continuousHigh = ($recent3.Count -eq 3 -and @($recent3 | Where-Object { $_.TotalWriteMBps -ge 0.5 }).Count -eq 3)
    $continuousMedium = ($recent3.Count -eq 3 -and @($recent3 | Where-Object { $_.TotalWriteMBps -ge 0.2 }).Count -eq 3)
    $blockedIn60 = 0
    $blockedRecently = $false
    $blockedPerMinuteHigh = $false
    if ($last60.Count -gt 0) {
        $blockedIn60 = ($last60 | Measure-Object BlockedLogInsertsSinceLastSample -Sum).Sum
        $blockedRecently = ($null -ne $blockedIn60 -and $blockedIn60 -gt 0)
        $blockedPerMinuteHigh = ($null -ne $blockedIn60 -and $blockedIn60 -ge 1000)
    }

    if ($blockedRecently) {
        $detail = "近 60 秒拦截 $blockedIn60 次，实际写盘均值 $avg60 MB/s"
        $level = "少量偏高已拦截"
        $text = "写盘评估：少量偏高已拦截"
        if ($blockedPerMinuteHigh -or $avg60 -ge 0.5 -or $continuousHigh) {
            $level = "异常偏高已拦截"
            $text = "写盘评估：异常偏高已拦截"
            $detail = "近 60 秒拦截 $blockedIn60 次；仍观察到进程写入均值 $avg60 MB/s"
        }
        return [pscustomobject]@{
            Level = $level
            Text = $text
            Detail = $detail
            Color = $script:ColorInfoBg
        }
    }

    $realWriteHigh = ($avg60 -ge 0.5 -or $continuousHigh)
    if ($realWriteHigh) {
        $reason = "近 60 秒均值 $avg60 MB/s"
        if ($continuousHigh) { $reason = "连续 3 次 >= 0.5 MB/s" }
        if (-not $script:BlockerInstalled) { $reason = "$reason；未安装拦截器，建议点击安装拦截器" }
        return [pscustomobject]@{
            Level = "异常"
            Text = "写盘评估：异常偏高"
            Detail = $reason
            Color = $script:ColorDangerBg
        }
    }

    if ($avg120 -lt 0.05 -and $max120 -lt 0.5 -and -not $continuousMedium) {
        return [pscustomobject]@{
            Level = "正常"
            Text = "写盘评估：正常"
            Detail = "近 2 分钟均值 $avg120 MB/s，峰值 $max120 MB/s"
            Color = $script:ColorSuccessBg
        }
    }

    return [pscustomobject]@{
        Level = "少量偏高"
        Text = "写盘评估：少量偏高"
        Detail = "近 2 分钟均值 $avg120 MB/s，峰值 $max120 MB/s"
        Color = $script:ColorWarningBg
    }
}

function Assert-SelfTest {
    [void](Get-PythonCommand)
    [void](Get-LogGuardStatus)
    Write-Output "SelfTest OK"
}

if ($SelfTest) {
    Assert-SelfTest
    exit 0
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$script:ColorSuccessText = [System.Drawing.Color]::FromArgb(22, 101, 52)
$script:ColorDangerText = [System.Drawing.Color]::FromArgb(180, 35, 24)
$script:ColorWarningText = [System.Drawing.Color]::FromArgb(146, 64, 14)
$script:ColorSuccessBg = [System.Drawing.Color]::FromArgb(220, 252, 231)
$script:ColorDangerBg = [System.Drawing.Color]::FromArgb(254, 226, 226)
$script:ColorWarningBg = [System.Drawing.Color]::FromArgb(254, 243, 199)
$script:ColorInfoBg = [System.Drawing.Color]::FromArgb(219, 234, 254)
$script:ColorNeutralBg = [System.Drawing.Color]::FromArgb(241, 245, 249)
$script:ColorRowWarningBg = [System.Drawing.Color]::FromArgb(255, 247, 214)
$script:ColorSuccessBorder = [System.Drawing.Color]::FromArgb(34, 197, 94)
$script:ColorDangerBorder = [System.Drawing.Color]::FromArgb(239, 68, 68)
$script:ColorWarningBorder = [System.Drawing.Color]::FromArgb(245, 158, 11)
$script:ColorInfoBorder = [System.Drawing.Color]::FromArgb(59, 130, 246)
$script:ColorNeutralBorder = [System.Drawing.Color]::FromArgb(148, 163, 184)
$script:ColorWindowBg = [System.Drawing.Color]::FromArgb(250, 250, 250)
$script:ColorSurfaceBg = [System.Drawing.Color]::FromArgb(255, 255, 255)
$script:ColorTableAltBg = [System.Drawing.Color]::FromArgb(248, 250, 252)
$script:ColorSubtleBorder = [System.Drawing.Color]::FromArgb(226, 232, 240)
$script:ColorWarningCellText = [System.Drawing.Color]::FromArgb(180, 83, 9)
$script:ColorDangerCellText = [System.Drawing.Color]::FromArgb(153, 27, 27)

$form = New-Object System.Windows.Forms.Form
$form.Text = "codex写盘异常检测"
$form.StartPosition = "CenterScreen"
$form.Size = New-Object System.Drawing.Size(900, 705)
$form.MinimumSize = New-Object System.Drawing.Size(900, 705)
$form.MaximumSize = New-Object System.Drawing.Size(900, 705)
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
$form.MaximizeBox = $false
$form.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 9)
$form.BackColor = $script:ColorWindowBg

$foregroundTimer = New-Object System.Windows.Forms.Timer
$foregroundTimer.Interval = 800
$foregroundTimer.Add_Tick({
    $foregroundTimer.Stop()
    $form.TopMost = $false
})

function Show-FormInForeground {
    $form.TopMost = $true
    $form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
    $form.Show()
    $form.BringToFront()
    [void]$form.Activate()
    $foregroundTimer.Start()
}

$form.Add_Shown({
    Show-FormInForeground
})

$evaluationBorderPanel = New-Object System.Windows.Forms.Panel
$evaluationBorderPanel.Location = New-Object System.Drawing.Point(12, 10)
$evaluationBorderPanel.Size = New-Object System.Drawing.Size(860, 52)
$evaluationBorderPanel.BackColor = $script:ColorNeutralBorder
$form.Controls.Add($evaluationBorderPanel)

$evaluationPanel = New-Object System.Windows.Forms.Panel
$evaluationPanel.Location = New-Object System.Drawing.Point(1, 1)
$evaluationPanel.Size = New-Object System.Drawing.Size(858, 50)
$evaluationPanel.BorderStyle = "None"
$evaluationPanel.BackColor = $script:ColorNeutralBg
$evaluationBorderPanel.Controls.Add($evaluationPanel)

$lblEvaluation = New-Object System.Windows.Forms.Label
$lblEvaluation.Text = "写盘评估：未检测"
$lblEvaluation.Location = New-Object System.Drawing.Point(14, 0)
$lblEvaluation.Size = New-Object System.Drawing.Size(240, 50)
$lblEvaluation.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 13, [System.Drawing.FontStyle]::Bold)
$lblEvaluation.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$evaluationPanel.Controls.Add($lblEvaluation)

$lblEvaluationDetail = New-Object System.Windows.Forms.Label
$lblEvaluationDetail.Text = "开始监测后生成结论"
$lblEvaluationDetail.Location = New-Object System.Drawing.Point(270, 0)
$lblEvaluationDetail.Size = New-Object System.Drawing.Size(390, 50)
$lblEvaluationDetail.AutoEllipsis = $true
$lblEvaluationDetail.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$evaluationPanel.Controls.Add($lblEvaluationDetail)

$btnMonitorToggle = New-Object System.Windows.Forms.Button
$btnMonitorToggle.Text = "开始监测"
$btnMonitorToggle.Location = New-Object System.Drawing.Point(679, 9)
$btnMonitorToggle.Size = New-Object System.Drawing.Size(160, 30)
$evaluationPanel.Controls.Add($btnMonitorToggle)

$lblMonitorHint = New-Object System.Windows.Forms.Label
$lblMonitorHint.Text = "提示：空闲状态只能说明当前无明显写盘；建议开启会话并运行任务后再观察。"
$lblMonitorHint.Location = New-Object System.Drawing.Point(18, 66)
$lblMonitorHint.Size = New-Object System.Drawing.Size(840, 22)
$lblMonitorHint.AutoEllipsis = $true
$lblMonitorHint.ForeColor = $script:ColorWarningText
$lblMonitorHint.BackColor = $script:ColorWindowBg
$form.Controls.Add($lblMonitorHint)

function New-Label([string]$Text, [int]$X, [int]$Y, [int]$W = 260, [int]$H = 22) {
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Location = New-Object System.Drawing.Point($X, $Y)
    $label.Size = New-Object System.Drawing.Size($W, $H)
    $label.AutoEllipsis = $true
    return $label
}

function New-Button([string]$Text, [int]$X, [int]$Y, [int]$W = 128) {
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Location = New-Object System.Drawing.Point($X, $Y)
    $button.Size = New-Object System.Drawing.Size($W, 30)
    return $button
}

$guardGroup = New-Object System.Windows.Forms.GroupBox
$guardGroup.Text = "防护状态"
$guardGroup.Location = New-Object System.Drawing.Point(12, 94)
$guardGroup.Size = New-Object System.Drawing.Size(860, 72)
$guardGroup.BackColor = $script:ColorSurfaceBg
$form.Controls.Add($guardGroup)

$lblBlocker = New-Label "拦截器：--" 16 30 210
$lblCounter = New-Label "历史累计拦截：-- 次" 246 30 210
$lblLastDelta = New-Label "上轮新增拦截：-- 次" 476 30 150
$btnBlockerToggle = New-Button "拦截器未安装" 640 24 90
$btnRestore = New-Button "监测时计数" 742 24 90
$guardGroup.Controls.AddRange(@($lblBlocker, $lblCounter, $lblLastDelta, $btnBlockerToggle, $btnRestore))

$fileGroup = New-Object System.Windows.Forms.GroupBox
$fileGroup.Text = "文件管理"
$fileGroup.Location = New-Object System.Drawing.Point(12, 174)
$fileGroup.Size = New-Object System.Drawing.Size(860, 112)
$fileGroup.BackColor = $script:ColorSurfaceBg
$form.Controls.Add($fileGroup)

$lblLogWriteFile = New-Label "Codex 日志写盘文件：-- MB，当前日志行数：-- 行（$script:LogDbPath）" 16 28 610
$lblBackupDir = New-Label "清理文件暂存目录：-- MB（$script:BackupDir）" 16 66 610
$btnOpenCodexLogDir = New-Object System.Windows.Forms.Button
$btnOpenCodexLogDir.Text = "打开目录"
$btnOpenCodexLogDir.Location = New-Object System.Drawing.Point(640, 24)
$btnOpenCodexLogDir.Size = New-Object System.Drawing.Size(90, 26)
$btnClearCurrent = New-Object System.Windows.Forms.Button
$btnClearCurrent.Text = "清理文件"
$btnClearCurrent.Location = New-Object System.Drawing.Point(742, 24)
$btnClearCurrent.Size = New-Object System.Drawing.Size(90, 26)
$btnOpenBackupDir = New-Object System.Windows.Forms.Button
$btnOpenBackupDir.Text = "打开目录"
$btnOpenBackupDir.Location = New-Object System.Drawing.Point(640, 62)
$btnOpenBackupDir.Size = New-Object System.Drawing.Size(90, 26)
$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text = "清空历史"
$btnClear.Location = New-Object System.Drawing.Point(742, 62)
$btnClear.Size = New-Object System.Drawing.Size(90, 26)
$fileGroup.Controls.AddRange(@($lblLogWriteFile, $btnOpenCodexLogDir, $btnClearCurrent, $lblBackupDir, $btnOpenBackupDir, $btnClear))

$monitorGroup = New-Object System.Windows.Forms.GroupBox
$monitorGroup.Text = "实时监测"
$monitorGroup.Location = New-Object System.Drawing.Point(12, 294)
$monitorGroup.Size = New-Object System.Drawing.Size(860, 130)
$monitorGroup.BackColor = $script:ColorSurfaceBg
$form.Controls.Add($monitorGroup)

$lblMonitorState = New-Label "监测状态：未开始" 16 26 210
$lblWrite = New-Label "总写入：-- MB/s" 246 26 210
$lblBlockedTotal = New-Label "本轮累计拦截：-- 次" 476 26 150
$lblSession = New-Label "当前会话：--" 16 58 210
$lblTopProcess = New-Label "最高进程：--" 246 58 210
$lblBlockedNow = New-Label "本次采样拦截：-- 次" 476 58 150
$lblCsv = New-Label "本次监测日志：--" 16 94 570
$btnOpenLogDir = New-Object System.Windows.Forms.Button
$btnOpenLogDir.Text = "打开目录"
$btnOpenLogDir.Location = New-Object System.Drawing.Point(640, 88)
$btnOpenLogDir.Size = New-Object System.Drawing.Size(90, 26)
$btnOpenCsv = New-Object System.Windows.Forms.Button
$btnOpenCsv.Text = "打开文件"
$btnOpenCsv.Location = New-Object System.Drawing.Point(742, 88)
$btnOpenCsv.Size = New-Object System.Drawing.Size(90, 26)
$monitorGroup.Controls.AddRange(@($lblMonitorState, $lblWrite, $lblTopProcess, $lblSession, $lblBlockedNow, $lblBlockedTotal, $lblCsv, $btnOpenLogDir, $btnOpenCsv))

$detailGroup = New-Object System.Windows.Forms.GroupBox
$detailGroup.Text = "监测明细"
$detailGroup.Location = New-Object System.Drawing.Point(12, 432)
$detailGroup.Size = New-Object System.Drawing.Size(860, 222)
$detailGroup.BackColor = $script:ColorSurfaceBg
$form.Controls.Add($detailGroup)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location = New-Object System.Drawing.Point(10, 24)
$grid.Size = New-Object System.Drawing.Size(840, 168)
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.ReadOnly = $true
$grid.SelectionMode = "FullRowSelect"
$grid.AutoSizeColumnsMode = "Fill"
$grid.RowHeadersVisible = $false
$grid.BackgroundColor = $script:ColorSurfaceBg
$grid.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$grid.GridColor = $script:ColorSubtleBorder
$grid.DefaultCellStyle.BackColor = $script:ColorSurfaceBg
$grid.AlternatingRowsDefaultCellStyle.BackColor = $script:ColorTableAltBg
$grid.ColumnHeadersDefaultCellStyle.BackColor = $script:ColorTableAltBg
$grid.EnableHeadersVisualStyles = $false
$detailGroup.Controls.Add($grid)

$columns = @(
    @("Time", "时间", 150),
    @("Status", "状态", 90),
    @("TotalWriteMBps", "写盘 MB/s", 90),
    @("TopProcess", "最高进程", 110),
    @("TopPID", "PID", 70),
    @("BlockedLogInsertsSinceLastSample", "本次采样拦截", 110),
    @("BlockedLogInsertsSinceStart", "本轮累计拦截", 110),
    @("ActiveThreadTitle", "会话", 170)
)
foreach ($column in $columns) {
    $gridColumn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $gridColumn.Name = $column[0]
    $gridColumn.HeaderText = $column[1]
    $gridColumn.Width = $column[2]
    [void]$grid.Columns.Add($gridColumn)
}

$lblMessage = New-Label "就绪" 10 196 840
$detailGroup.Controls.Add($lblMessage)

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 5000
$restartTimer = New-Object System.Windows.Forms.Timer
$restartTimer.Interval = 1000

function Set-Message([string]$Text) {
    $lblMessage.Text = $Text
}

function Get-EvaluationBorderColor($Evaluation) {
    switch ($Evaluation.Level) {
        "正常" { return $script:ColorSuccessBorder }
        "异常" { return $script:ColorDangerBorder }
        "异常偏高已拦截" { return $script:ColorDangerBorder }
        "少量偏高" { return $script:ColorWarningBorder }
        "少量偏高已拦截" { return $script:ColorWarningBorder }
        "观察中" { return $script:ColorWarningBorder }
        default { return $script:ColorNeutralBorder }
    }
}

function Get-EvaluationTextColor($Evaluation) {
    switch ($Evaluation.Level) {
        "异常" { return $script:ColorDangerText }
        "异常偏高已拦截" { return $script:ColorDangerText }
        "少量偏高" { return $script:ColorWarningText }
        "少量偏高已拦截" { return $script:ColorWarningText }
        default { return [System.Drawing.Color]::Black }
    }
}

function Update-EvaluationUi($Evaluation) {
    $lblEvaluation.Text = $Evaluation.Text
    $lblEvaluation.ForeColor = Get-EvaluationTextColor $Evaluation
    $lblEvaluationDetail.Text = $Evaluation.Detail
    $evaluationPanel.BackColor = $Evaluation.Color
    $evaluationBorderPanel.BackColor = Get-EvaluationBorderColor $Evaluation
}

function Set-MonitorHint([string]$Text, [System.Drawing.Color]$Color) {
    $lblMonitorHint.Text = $Text
    $lblMonitorHint.ForeColor = $Color
}

function Format-CountUnit($Value, [string]$Unit) {
    if ($null -eq $Value -or $Value -eq "") {
        return "-- $Unit"
    }
    return "$Value $Unit"
}

function Check-RestartRequests {
    if ($script:RestartPromptActive -or -not (Test-Path -LiteralPath $script:InstanceDir)) {
        return
    }

    $request = Get-ChildItem -LiteralPath $script:InstanceDir -Filter "restart-request-*.txt" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime |
        Select-Object -First 1
    if (-not $request) {
        return
    }

    $script:RestartPromptActive = $true
    $requestId = [System.IO.Path]::GetFileNameWithoutExtension($request.Name).Replace("restart-request-", "")
    $responsePath = Join-Path $script:InstanceDir "restart-response-$requestId.txt"
    $confirm = [System.Windows.Forms.MessageBox]::Show("检测到新的启动请求。是否关闭当前窗口并打开新的窗口？", "重新打开", "YesNo", "Question")
    if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
        [System.IO.File]::WriteAllText($responsePath, "accepted", (New-Object System.Text.UTF8Encoding($false)))
        Remove-Item -LiteralPath $request.FullName -Force -ErrorAction SilentlyContinue
        $script:RestartCloseRequested = $true
        $form.Close()
        return
    }

    [System.IO.File]::WriteAllText($responsePath, "declined", (New-Object System.Text.UTF8Encoding($false)))
    Remove-Item -LiteralPath $request.FullName -Force -ErrorAction SilentlyContinue
    $script:RestartPromptActive = $false
}

function Set-MonitoringUiState([bool]$Monitoring) {
    $btnBlockerToggle.Enabled = -not $Monitoring
    $btnRestore.Enabled = -not $Monitoring
    $btnClearCurrent.Enabled = $true
    $btnClear.Enabled = $true
    if ($Monitoring) {
        $btnMonitorToggle.Text = "停止监测"
    } else {
        $btnMonitorToggle.Text = "开始监测"
    }
    $btnMonitorToggle.Enabled = $true
    $btnOpenLogDir.Enabled = $true
    $btnOpenCsv.Enabled = $true
    Update-CountingButtonText
    Update-BlockerToggleButtonText
}

function Refresh-StatusUi {
    try {
        $status = Get-LogGuardStatus
        $script:BlockerInstalled = [bool]$status.trigger_installed
        $lblBlocker.Text = Get-DisplayBlockerStatus $status
        if ($status.trigger_installed) {
            $lblBlocker.ForeColor = $script:ColorSuccessText
        } else {
            $lblBlocker.ForeColor = $script:ColorDangerText
        }
        $logWriteMB = [math]::Round(($status.DbMB + $status.WalMB + $status.ShmMB), 3)
        $lblLogWriteFile.Text = "Codex 日志写盘文件：$logWriteMB MB，当前日志行数：$(Format-CountUnit $status.logs_count '行')（$script:LogDbPath）"
        $lblBackupDir.Text = "清理文件暂存目录：$($status.BackupDirMB) MB（$script:BackupDir）"
        $lblCounter.Text = "历史累计拦截：$(Format-CountUnit $status.counter_total '次')"
        $lblLastDelta.Text = "上轮新增拦截：$(Format-CountUnit $status.last_session_delta '次')"
        Update-CountingButtonText
        Update-BlockerToggleButtonText
        if ($status.error) {
            Set-Message "状态读取异常：$($status.error)"
        } else {
            Set-Message "状态已刷新"
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "刷新状态失败", "OK", "Error") | Out-Null
        Set-Message "刷新状态失败"
    }
}

function Start-Monitoring {
    if ($script:IsMonitoring) {
        return
    }

    try {
        if (-not (Test-Path -LiteralPath $script:LogDir)) {
            New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
        }
        $script:CurrentCsvPath = Join-Path $script:LogDir ("codex-write-" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".csv")
        $status = Get-LogGuardStatus
        $script:MonitorHadBlockerAtStart = [bool]$status.trigger_installed
        if (-not $script:MonitorHadBlockerAtStart) {
            $script:MonitorStartCounter = Invoke-LogCounterAction "read"
            $script:CountingActiveThisRun = $false
        } elseif ($script:CountingEnabled) {
            $script:MonitorStartCounter = Invoke-LogCounterAction "enable"
            $script:CountingActiveThisRun = $true
        } else {
            Invoke-LogCounterAction "restore" | Out-Null
            $script:MonitorStartCounter = Invoke-LogCounterAction "read"
            $script:CountingActiveThisRun = $false
        }
        $script:MonitorPreviousCounter = $script:MonitorStartCounter
        $script:EvaluationSamples = @()
        $script:SampleIndex = 0
        $grid.Rows.Clear()
        $script:IsMonitoring = $true
        if ($script:MonitorHadBlockerAtStart) {
            $lblMonitorState.Text = "监测状态：正在监测"
            Set-MonitorHint "提示：空闲状态只能说明当前无明显写盘；建议开启会话并运行任务后再观察。" $script:ColorWarningText
        } else {
            $lblMonitorState.Text = "监测状态：正在监测（未安装拦截器）"
            Set-MonitorHint "提示：当前未安装拦截器，只监测真实写盘；建议点击[安装拦截器]。" $script:ColorWarningText
        }
        $lblCsv.Text = "本次监测日志：$script:CurrentCsvPath"
        Set-MonitoringUiState $true
        $timer.Start()
        Add-MonitorSample
        Set-Message "监测已开始"
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "开始监测失败", "OK", "Error") | Out-Null
        Stop-Monitoring -Silent
    }
}

function Stop-Monitoring([switch]$Silent) {
    if (-not $script:IsMonitoring) {
        return
    }

    $timer.Stop()
    if ($script:MonitorHadBlockerAtStart) {
        try {
            Invoke-LogCounterAction "restore" | Out-Null
        } catch {
            if (-not $Silent) {
                [System.Windows.Forms.MessageBox]::Show("停止计数失败：$($_.Exception.Message)", "停止监测", "OK", "Warning") | Out-Null
            }
        }
    }
    $script:IsMonitoring = $false
    $script:CountingActiveThisRun = $false
    $script:MonitorHadBlockerAtStart = $false
    $lblMonitorState.Text = "监测状态：已停止"
    Set-MonitorHint "提示：空闲状态只能说明当前无明显写盘；建议开启会话并运行任务后再观察。" $script:ColorWarningText
    Set-MonitoringUiState $false
    Refresh-StatusUi
    if (-not $Silent) {
        Set-Message "监测已停止"
    }
}

function Apply-MonitorSample($sample) {
        Write-MonitorCsvRow $sample
        $script:SampleIndex += 1

        $lblWrite.Text = "总写入：$($sample.TotalWriteMBps) MB/s"
        $lblTopProcess.Text = "最高进程：$($sample.TopWriteMBps) MB/s | $($sample.TopProcess)"
        $lblSession.Text = "当前会话：$($sample.ActiveThreadTitle)"
        $lblBlockedNow.Text = "本次采样拦截：$(Format-CountUnit $sample.BlockedLogInsertsSinceLastSample '次')"
        $lblBlockedTotal.Text = "本轮累计拦截：$(Format-CountUnit $sample.BlockedLogInsertsSinceStart '次')"
        if (-not $script:MonitorHadBlockerAtStart) {
            Set-MonitorHint "提示：当前未安装拦截器，只监测真实写盘；建议点击[安装拦截器]。" $script:ColorWarningText
        } elseif ($sample.TaskState -eq "最近有会话活动") {
            Set-MonitorHint "提示：已检测到近期会话活动，当前数据可用于观察任务运行时写盘。" $script:ColorSuccessText
        } else {
            Set-MonitorHint "提示：未检测到近期会话活动；建议在 Codex 中运行一个任务，再观察写盘和拦截变化。" $script:ColorWarningText
        }
        $updatedEvaluationSamples = @($script:EvaluationSamples + [pscustomobject]@{
            Time = [datetime]::ParseExact($sample.Time, "yyyy-MM-dd HH:mm:ss", $null)
            TotalWriteMBps = [double]$sample.TotalWriteMBps
            BlockedLogInsertsSinceLastSample = [int]$sample.BlockedLogInsertsSinceLastSample
            TaskState = $sample.TaskState
        })
        $script:EvaluationSamples = @($updatedEvaluationSamples | Select-Object -Last 24)
        Update-EvaluationUi (Get-WriteEvaluation $script:EvaluationSamples)

        $grid.Rows.Insert(0, 1)
        $row = $grid.Rows[0]
        foreach ($column in $columns) {
            $name = $column[0]
            $value = $sample.PSObject.Properties[$name].Value
            if ($name -eq "BlockedLogInsertsSinceLastSample" -or $name -eq "BlockedLogInsertsSinceStart") {
                $value = Format-CountUnit $value "次"
            }
            $row.Cells[$name].Value = $value
        }
        if ($sample.Status -eq "已拦截") {
            $row.DefaultCellStyle.BackColor = $script:ColorDangerBg
        } elseif ($sample.Status -eq "写盘偏高") {
            $row.DefaultCellStyle.BackColor = $script:ColorRowWarningBg
        }
        if ($sample.Status -eq "已拦截") {
            $row.Cells["Status"].Style.ForeColor = $script:ColorDangerCellText
        } elseif ($sample.Status -eq "写盘偏高") {
            $row.Cells["Status"].Style.ForeColor = $script:ColorWarningCellText
        }
        if ([double]$sample.TotalWriteMBps -ge $script:MonitorWarnMBps) {
            $row.Cells["TotalWriteMBps"].Style.ForeColor = $script:ColorWarningCellText
        }
        if ([int]$sample.BlockedLogInsertsSinceLastSample -gt 0) {
            $row.Cells["BlockedLogInsertsSinceLastSample"].Style.ForeColor = $script:ColorDangerCellText
        }
        if ($grid.Rows.Count -gt 200) {
            $grid.Rows.RemoveAt($grid.Rows.Count - 1)
        }
        $grid.FirstDisplayedScrollingRowIndex = 0
        Refresh-StatusUi
        Set-Message "采样 $script:SampleIndex 已记录"
}

function Add-MonitorSample {
    if (-not $script:IsMonitoring) {
        return
    }

    try {
        $sample = New-MonitorSample
        Apply-MonitorSample $sample
    } catch {
        Set-Message "采样失败：$($_.Exception.Message)"
    }
}

$timer.Add_Tick({ Add-MonitorSample })
$restartTimer.Add_Tick({ Check-RestartRequests })

$btnOpenCodexLogDir.Add_Click({
    if (-not (Test-Path -LiteralPath $script:CodexDir)) {
        [System.Windows.Forms.MessageBox]::Show("没有找到 Codex 日志目录：$script:CodexDir", "打开目录", "OK", "Information") | Out-Null
        return
    }
    Start-Process explorer.exe $script:CodexDir
})
$btnOpenBackupDir.Add_Click({
    if (-not (Test-Path -LiteralPath $script:BackupDir)) {
        New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null
    }
    Start-Process explorer.exe $script:BackupDir
})

function Invoke-ClearLogFilesFromUi {
    $confirm = [System.Windows.Forms.MessageBox]::Show("清理会自动清理上一次的备份文件：先清空 logs_backup 暂存目录，再把当前 logs_2.sqlite* 移动进去。请确认 Codex 已完全退出。继续吗？", "清理文件", "YesNo", "Warning")
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
        return
    }
    try {
        $message = Backup-And-ClearLogs
        [System.Windows.Forms.MessageBox]::Show($message, "清理完成", "OK", "Information") | Out-Null
        Refresh-StatusUi
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "清理失败", "OK", "Error") | Out-Null
    }
}

function Invoke-ClearBackupHistoryFromUi {
    $confirm = [System.Windows.Forms.MessageBox]::Show("只会清空 logs_backup 暂存目录中的历史文件，不会处理当前 logs_2.sqlite。继续吗？", "清空历史", "YesNo", "Warning")
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
        return
    }
    try {
        $message = Clear-BackupHistory
        [System.Windows.Forms.MessageBox]::Show($message, "清空完成", "OK", "Information") | Out-Null
        Refresh-StatusUi
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "清空失败", "OK", "Error") | Out-Null
    }
}

$btnClearCurrent.Add_Click({ Invoke-ClearLogFilesFromUi })
$btnClear.Add_Click({ Invoke-ClearBackupHistoryFromUi })
$btnBlockerToggle.Add_Click({
    $status = Get-LogGuardStatus
    if ($status.trigger_installed) {
        $confirmText = if ($script:IsMonitoring) {
            "卸载后本轮监测将不再拦截和计数，只继续监测真实写盘。确定卸载拦截器吗？"
        } else {
            "卸载后 Codex 将重新写入 logs 表。确定卸载拦截器吗？"
        }
        $confirm = [System.Windows.Forms.MessageBox]::Show($confirmText, "卸载拦截器", "YesNo", "Warning")
        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
            return
        }
        try {
            Invoke-LogBlockerAction "remove"
            $script:BlockerInstalled = $false
            if ($script:IsMonitoring) {
                $currentCounter = Invoke-LogCounterAction "read"
                $script:MonitorStartCounter = $currentCounter
                $script:MonitorPreviousCounter = $currentCounter
                $script:CountingActiveThisRun = $false
                $script:MonitorHadBlockerAtStart = $false
                $lblMonitorState.Text = "监测状态：正在监测（未安装拦截器）"
                $lblBlockedNow.Text = "本次采样拦截：0 次"
                $lblBlockedTotal.Text = "本轮累计拦截：0 次"
                Set-MonitorHint "提示：当前未安装拦截器，只监测真实写盘；建议点击[安装拦截器]。" $script:ColorWarningText
            }
            Refresh-StatusUi
            [System.Windows.Forms.MessageBox]::Show("已卸载拦截器。", "完成", "OK", "Information") | Out-Null
        } catch {
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "卸载失败", "OK", "Error") | Out-Null
        }
    } else {
        try {
            if ($script:IsMonitoring -and $script:CountingEnabled) {
                $currentCounter = Invoke-LogCounterAction "enable"
                $script:MonitorStartCounter = $currentCounter
                $script:MonitorPreviousCounter = $currentCounter
                $script:CountingActiveThisRun = $true
            } else {
                Invoke-LogBlockerAction "install"
                if ($script:IsMonitoring) {
                    $currentCounter = Invoke-LogCounterAction "read"
                    $script:MonitorStartCounter = $currentCounter
                    $script:MonitorPreviousCounter = $currentCounter
                    $script:CountingActiveThisRun = $false
                } else {
                    $script:CountingEnabled = $true
                }
            }
            $script:BlockerInstalled = $true
            if ($script:IsMonitoring) {
                $script:MonitorHadBlockerAtStart = $true
                $lblMonitorState.Text = "监测状态：正在监测"
                $lblBlockedNow.Text = "本次采样拦截：0 次"
                $lblBlockedTotal.Text = "本轮累计拦截：0 次"
                if ($script:CountingActiveThisRun) {
                    Set-MonitorHint "提示：已在监测中安装拦截器，本轮拦截计数从安装时重新开始。" $script:ColorSuccessText
                } else {
                    Set-MonitorHint "提示：已在监测中安装拦截器；计数已关闭，本轮只监测写盘。" $script:ColorWarningText
                }
            }
            Refresh-StatusUi
            $message = if ($script:CountingEnabled) {
                "已安装拦截器，拦截次数已开启统计。"
            } else {
                "已安装拦截器，当前计数为关闭状态。"
            }
            [System.Windows.Forms.MessageBox]::Show($message, "完成", "OK", "Information") | Out-Null
        } catch {
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "安装失败", "OK", "Error") | Out-Null
        }
    }
})
$btnRestore.Add_Click({
    try {
        $status = Get-LogGuardStatus
        $script:BlockerInstalled = [bool]$status.trigger_installed
        if ($script:CountingEnabled) {
            Invoke-LogCounterAction "reset" | Out-Null
            $script:CountingEnabled = $false
            $message = "已关闭拦截次数统计，并已清空历史累计拦截次数。开始监测时也不会计数，少量偏高已拦截/异常偏高已拦截相关结论可能不准确。"
        } else {
            $script:CountingEnabled = $true
            $message = if ($script:BlockerInstalled) {
                "已开启拦截次数统计。开始监测时会临时计数。"
            } else {
                "已开启拦截次数统计。安装拦截器后，开始监测时会计数。"
            }
        }
        Refresh-StatusUi
        [System.Windows.Forms.MessageBox]::Show($message, "完成", "OK", "Information") | Out-Null
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "切换计数失败", "OK", "Error") | Out-Null
    }
})
$btnMonitorToggle.Add_Click({
    if ($script:IsMonitoring) {
        Stop-Monitoring
    } else {
        Start-Monitoring
    }
})
$btnOpenLogDir.Add_Click({
    if (-not (Test-Path -LiteralPath $script:LogDir)) {
        New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
    }
    Start-Process explorer.exe $script:LogDir
})
$btnOpenCsv.Add_Click({
    if ($script:CurrentCsvPath -and (Test-Path -LiteralPath $script:CurrentCsvPath)) {
        Start-Process $script:CurrentCsvPath
    } else {
        [System.Windows.Forms.MessageBox]::Show("当前还没有日志文件。", "打开日志文件", "OK", "Information") | Out-Null
    }
})

$form.Add_FormClosing({
    param($sender, $event)
    if ($script:IsMonitoring) {
        if (-not $script:RestartCloseRequested) {
            $confirm = [System.Windows.Forms.MessageBox]::Show("正在监测，关闭前将停止计数并恢复拦截器，是否继续？", "关闭确认", "YesNo", "Warning")
            if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
                $event.Cancel = $true
                return
            }
        }
        Stop-Monitoring -Silent
    }
})

$form.Add_FormClosed({
    $restartTimer.Stop()
    $timer.Stop()
    $foregroundTimer.Stop()
    if ($script:InstanceMutex) {
        try {
            $script:InstanceMutex.ReleaseMutex()
        } catch {
        }
        $script:InstanceMutex.Dispose()
        $script:InstanceMutex = $null
    }
})

Refresh-StatusUi
Set-MonitoringUiState $false
Update-EvaluationUi (Get-WriteEvaluation @())
$restartTimer.Start()
[void][System.Windows.Forms.Application]::Run($form)
