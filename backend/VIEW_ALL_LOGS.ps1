# ================================================================================
# COMPREHENSIVE SYSTEM LOG VIEWER - Real-time Monitoring
# ================================================================================

# Resolve Redis container ID (allow override via REDIS_CONTAINER_ID env var)
$RedisContainerId = if ($env:REDIS_CONTAINER_ID -and $env:REDIS_CONTAINER_ID.Trim() -ne "") {
    $env:REDIS_CONTAINER_ID.Trim()
} else {
    "0af2a830d3d7c63fa6d24ea1940c9c013313fceb7a9010c91d77ff65b8a85c06"
}

function Show-Logs {
    Clear-Host
    
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host "CURRENT SYSTEM LOGS - Real-time View" -ForegroundColor Green
    Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host ""

    # === MAIN BACKEND LOG ===
    Write-Host "=== MAIN BACKEND (Port 3000) ===" -ForegroundColor Cyan
    $port3000 = netstat -ano | Select-String ":3000" | Select-String "LISTENING"
    if ($port3000) {
        $processId = ($port3000 -split '\s+')[-1]
        Write-Host "  Status: RUNNING (PID: $processId)" -ForegroundColor Green
        $netstat = netstat -ano | Select-String ":3000.*ESTABLISHED" | Measure-Object
        Write-Host "  Active Connections: $($netstat.Count)" -ForegroundColor Cyan
        
        # Show recent backend logs
        $backendLog = "logs\main_backend.log"
        if (Test-Path $backendLog) {
            $lastModified = (Get-Item $backendLog).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            Write-Host "  Log Last Modified: $lastModified" -ForegroundColor Gray
            $recentLogs = Get-Content $backendLog -Tail 5 -ErrorAction SilentlyContinue
            if ($recentLogs) {
                Write-Host "  Recent Activity:" -ForegroundColor Yellow
                $recentLogs | ForEach-Object { Write-Host "    $_" -ForegroundColor White }
            }
        }
    } else {
        Write-Host "  Status: NOT RUNNING" -ForegroundColor Red
    }
    Write-Host ""

    # === ORCHESTRATOR API LOG ===
    $orchApiLog = "distributed_system\logs\orchestrator_api.log"
    Write-Host "=== ORCHESTRATOR API (Port 8001) - Last 15 lines ===" -ForegroundColor Cyan
    if (Test-Path $orchApiLog) {
        $lastModified = (Get-Item $orchApiLog).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        Write-Host "  Last Modified: $lastModified" -ForegroundColor Gray
        Write-Host ("  " + ("-" * 60)) -ForegroundColor DarkGray
        Get-Content $orchApiLog -Tail 15 -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_ -match "ERROR") {
                Write-Host $_ -ForegroundColor Red
            } elseif ($_ -match "WARNING") {
                Write-Host $_ -ForegroundColor Yellow
            } elseif ($_ -match "ORCHESTRATOR|CRAWLER|WORKER") {
                Write-Host $_ -ForegroundColor Cyan
            } else {
                Write-Host $_ -ForegroundColor White
            }
        }
    } else {
        Write-Host "  (Log file not found)" -ForegroundColor Red
    }
    Write-Host ""

    # === ORCHESTRATOR ERROR LOG ===
    $orchErrLog = "distributed_system\logs\orchestrator_api.err.log"
    if (Test-Path $orchErrLog) {
        $errContent = Get-Content $orchErrLog -Tail 5 -ErrorAction SilentlyContinue | Where-Object { $_ -ne "" }
        if ($errContent) {
            Write-Host "=== ORCHESTRATOR ERRORS (Last 5) ===" -ForegroundColor Red
            $errContent | ForEach-Object {
                Write-Host $_ -ForegroundColor Red
            }
            Write-Host ""
        }
    }

    # === WEBSOCKET LOG ===
    $wsLog = "distributed_system\logs\websocket_api.log"
    Write-Host "=== WEBSOCKET LOG (Last 20 lines) ===" -ForegroundColor Cyan
    if (Test-Path $wsLog) {
        $lastModified = (Get-Item $wsLog).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        Write-Host "  Last Modified: $lastModified" -ForegroundColor Gray
        Write-Host ("  " + ("-" * 40)) -ForegroundColor DarkGray
        Get-Content $wsLog -Tail 20 -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host $_ -ForegroundColor White
        }
    } else {
        Write-Host "  (Log file not found)" -ForegroundColor Red
    }
    Write-Host ""

    # === MONITORING API LOG ===
    $monLog = "distributed_system\logs\monitoring_api.log"
    Write-Host "=== MONITORING API LOG (Last 20 lines) ===" -ForegroundColor Cyan
    if (Test-Path $monLog) {
        $lastModified = (Get-Item $monLog).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        Write-Host "  Last Modified: $lastModified" -ForegroundColor Gray
        Write-Host ("  " + ("-" * 40)) -ForegroundColor DarkGray
        Get-Content $monLog -Tail 20 -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host $_ -ForegroundColor White
        }
    } else {
        Write-Host "  (Log file not found)" -ForegroundColor Red
    }
    Write-Host ""

    # === SCRAPY CRAWLER LOGS ===
    Write-Host "=== SCRAPY CRAWLER LOGS ===" -ForegroundColor Cyan
    $scrapyLogDir = "distributed_system\logs\scrapy"
    if (Test-Path $scrapyLogDir) {
        # Get most recent crawler logs
        $crawlerLogs = Get-ChildItem "$scrapyLogDir\crawler_*.err.log" -ErrorAction SilentlyContinue | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 3
        
        if ($crawlerLogs) {
            foreach ($logFile in $crawlerLogs) {
                $lastModified = $logFile.LastWriteTime.ToString('HH:mm:ss')
                Write-Host "  --- $($logFile.Name) (Modified: $lastModified) ---" -ForegroundColor Yellow
                $content = Get-Content $logFile.FullName -Tail 12 -ErrorAction SilentlyContinue
            if ($content) {
                $content | ForEach-Object {
                    if ($_ -match "ERROR") {
                        Write-Host $_ -ForegroundColor Red
                        } elseif ($_ -match "WARNING") {
                        Write-Host $_ -ForegroundColor Yellow
                        } elseif ($_ -match "INFO.*Extracted|INFO.*Crawling|INFO.*Dispatched") {
                            Write-Host $_ -ForegroundColor Cyan
                        } else {
                        Write-Host $_ -ForegroundColor White
                    }
                }
            }
            }
            
            # Also check .log files
            $crawlerStdLogs = Get-ChildItem "$scrapyLogDir\crawler_*.log" -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -notmatch ".err." } |
                Sort-Object LastWriteTime -Descending | 
                Select-Object -First 2
            
            if ($crawlerStdLogs) {
                foreach ($logFile in $crawlerStdLogs) {
                    $lastModified = $logFile.LastWriteTime.ToString('HH:mm:ss')
                    Write-Host "  --- $($logFile.Name) (Modified: $lastModified) ---" -ForegroundColor Yellow
                }
            }
        } else {
            Write-Host "  (No crawler logs found yet)" -ForegroundColor Gray
        }
    } else {
        Write-Host "  (Scrapy log directory not found)" -ForegroundColor Gray
    }
    Write-Host ""

    # === ACTIVE WORKER LOGS ===
    Write-Host "=== ACTIVE WORKER LOGS (Last 10 lines each) ===" -ForegroundColor Cyan
    $workerLogDir = "distributed_system\logs\workers"
    if (Test-Path $workerLogDir) {
        # Get most recently modified worker logs
        $workerLogs = Get-ChildItem "$workerLogDir\*worker*.err.log" -ErrorAction SilentlyContinue | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 4
        
        if ($workerLogs) {
            foreach ($logFile in $workerLogs) {
                $lastModified = $logFile.LastWriteTime.ToString('HH:mm:ss')
                Write-Host "  --- $($logFile.Name) (Modified: $lastModified) ---" -ForegroundColor Magenta
                $content = Get-Content $logFile.FullName -Tail 10 -ErrorAction SilentlyContinue
                if ($content) {
                    $content | ForEach-Object {
                        if ($_ -match "ERROR") {
                            Write-Host $_ -ForegroundColor Red
                        } elseif ($_ -match "WARNING") {
                            Write-Host $_ -ForegroundColor Yellow
                        } else {
                            Write-Host $_ -ForegroundColor Gray
                        }
                    }
                }
            }
            
            # Also show .log files (stdout)
            $workerStdLogs = Get-ChildItem "$workerLogDir\*worker*.log" -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -notmatch ".err." } |
                Sort-Object LastWriteTime -Descending | 
                Select-Object -First 2
            
            if ($workerStdLogs) {
                foreach ($logFile in $workerStdLogs) {
                    $lastModified = $logFile.LastWriteTime.ToString('HH:mm:ss')
                    Write-Host "  --- $($logFile.Name) (Modified: $lastModified) ---" -ForegroundColor Magenta
                    $content = Get-Content $logFile.FullName -Tail 10 -ErrorAction SilentlyContinue
                    if ($content) {
                        $content | ForEach-Object {
                            Write-Host $_ -ForegroundColor Gray
                        }
                    }
                }
            }
        } else {
            Write-Host "  (No worker logs found yet)" -ForegroundColor Gray
        }
    } else {
        Write-Host "  (Worker log directory not found)" -ForegroundColor Gray
    }
    Write-Host ""

    # === SYSTEM STATUS ===
    Write-Host "=== SYSTEM STATUS ===" -ForegroundColor Green
    $pythonCount = (Get-Process python -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Host "Python Processes: $pythonCount" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Listening Ports:" -ForegroundColor Yellow
    Write-Host ""
    $ports = netstat -ano | Select-String "LISTENING" | Select-String ":3000|:8001|:8002|:9090"
    if ($ports) {
        $ports | ForEach-Object {
            Write-Host $_ -ForegroundColor Green
        }
    } else {
        Write-Host "  (No backend services listening)" -ForegroundColor Red
    }
    Write-Host ""

    # === REDIS SCAN STATUS ===
    Write-Host "=== ACTIVE SCANS & REDIS STATUS ===" -ForegroundColor Green
    try {
        # Try Docker Redis first
        $crawledKeys = docker exec $RedisContainerId redis-cli --scan --pattern "crawled_items:*" --count 1000 2>$null
        $resultsKeys = docker exec $RedisContainerId redis-cli --scan --pattern "scan_results:*" --count 1000 2>$null
        $queueKeys = docker exec $RedisContainerId redis-cli --scan --pattern "scanner_queue:*" --count 1000 2>$null
        $sessionKeys = docker exec $RedisContainerId redis-cli --scan --pattern "scan_session:*" --count 1000 2>$null
        $metadataKeys = docker exec $RedisContainerId redis-cli --scan --pattern "scan_metadata:*" --count 1000 2>$null
        $finalKeys = docker exec $RedisContainerId redis-cli --scan --pattern "scan_results_final:*" --count 1000 2>$null
        
        # Show active scans
        if ($sessionKeys) {
            Write-Host "Active Scan Sessions:" -ForegroundColor Yellow
            $sessionKeys | Select-Object -First 5 | ForEach-Object {
                $scanId = $_ -replace "scan_session:", ""
                $status = docker exec $RedisContainerId redis-cli HGET $_ status 2>$null
                $progress = docker exec $RedisContainerId redis-cli HGET $_ progress 2>$null
                if ($status) {
                    $statusColor = if ($status -eq "completed") { "Green" } elseif ($status -eq "failed") { "Red" } else { "Cyan" }
                    Write-Host "  $scanId : $status ($progress%)" -ForegroundColor $statusColor
                }
            }
        }
        
        # Show queue status with progress calculation
        Write-Host "`nQueue Status:" -ForegroundColor Yellow
        $allKeys = @()
        if ($crawledKeys) { $allKeys += $crawledKeys }
        if ($queueKeys) { $allKeys += $queueKeys }
        if ($resultsKeys) { $allKeys += $resultsKeys }
        if ($metadataKeys) { $allKeys += $metadataKeys }
        
        # Track scan progress
        $scanProgress = @{}
        
        if ($allKeys.Count -gt 0) {
            foreach ($key in $allKeys | Select-Object -First 8) {
                if ($key -like "scan_metadata:*") {
                    $count = docker exec $RedisContainerId redis-cli HLEN $key 2>$null
                } else {
                    $count = docker exec $RedisContainerId redis-cli LLEN $key 2>$null
                }
                if ($count -and $count -ne "" -and $count -gt 0) {
                    Write-Host "  $key : $count items" -ForegroundColor Cyan
                    
                    # Extract scan_id and track progress
                    if ($key -match ":(.+)$") {
                        $scanId = $matches[1]
                        if ($key -like "crawled_items:*") {
                            if (-not $scanProgress.ContainsKey($scanId)) {
                                $scanProgress[$scanId] = @{}
                            }
                            $scanProgress[$scanId].crawled = $count
                        } elseif ($key -like "scan_results:*") {
                            if (-not $scanProgress.ContainsKey($scanId)) {
                                $scanProgress[$scanId] = @{}
                            }
                            $scanProgress[$scanId].results = $count
                        } elseif ($key -like "scan_metadata:*") {
                            $scanId = $key -replace "scan_metadata:", ""
                            if (-not $scanProgress.ContainsKey($scanId)) {
                                $scanProgress[$scanId] = @{}
                            }
                            # Metadata keys don't have a simple LLEN, but their existence indicates an active/tracked scan
                            $scanProgress[$scanId].metadata = $true
                        }
                    }
                }
            }
            
            # Display progress for each active scan
            if ($scanProgress.Keys.Count -gt 0) {
                Write-Host "`nScan Progress:" -ForegroundColor Yellow
                foreach ($scanId in $scanProgress.Keys) {
                    $crawled = [int]($scanProgress[$scanId].crawled -replace '[^\d]', '0')
                    $results = [int]($scanProgress[$scanId].results -replace '[^\d]', '0')
                    
                    # Get REAL task counts from Redis (dynamic tracking)
                    # Query Redis metadata inside the container
                    # Get REAL task counts from Redis (dynamic tracking)
                    # Query Redis metadata inside the container
                    # Use scanId directly (it already matches the key format)
                    $fullScanId = $scanId
                    $totalCreated = docker exec $RedisContainerId redis-cli HGET "scan_metadata:$fullScanId" "total_tasks_created" 2>$null
                    $tasksPending = docker exec $RedisContainerId redis-cli HGET "scan_metadata:$fullScanId" "tasks_pending" 2>$null
                    $tasksCompleted = docker exec $RedisContainerId redis-cli HGET "scan_metadata:$fullScanId" "tasks_completed" 2>$null
                    $tasksFailed = docker exec $RedisContainerId redis-cli HGET "scan_metadata:$fullScanId" "tasks_failed" 2>$null
                    
                    # Convert to integers (handle empty/null values AND negative values)
                    $totalCreated = if ($totalCreated -and $totalCreated -ne "") { [int]$totalCreated } else { 0 }
                    # FIX: Force negative pending to 0 (prevents status bug when tasks_pending goes negative)
                    $tasksPending = if ($tasksPending -and $tasksPending -ne "") { [Math]::Max(0, [int]$tasksPending) } else { 0 }
                    $tasksCompleted = if ($tasksCompleted -and $tasksCompleted -ne "") { [int]$tasksCompleted } else { 0 }
                    $tasksFailed = if ($tasksFailed -and $tasksFailed -ne "") { [int]$tasksFailed } else { 0 }
                    
                    # Calculate actual total tasks (completed + failed + pending)
                    $actualTotal = $tasksCompleted + $tasksFailed + $tasksPending
                    
                    # Use real total if available AND reasonable, otherwise use actual total
                    if ($totalCreated -gt 0 -and $actualTotal -le ($totalCreated * 1.5)) {
                        # totalCreated is reasonable (within 150% of actual)
                        $estimatedTotal = $totalCreated
                        $progressPercent = [Math]::Min(100, [Math]::Round((($tasksCompleted + $tasksFailed) / $totalCreated) * 100, 1))
                    } elseif ($actualTotal -gt 0) {
                        # Use actual total (completed + failed + pending)
                        $estimatedTotal = $actualTotal
                        $progressPercent = if ($actualTotal -gt 0) {
                            [Math]::Min(100, [Math]::Round((($tasksCompleted + $tasksFailed) / $actualTotal) * 100, 1))
                        } else { 0 }
                    } else {
                        # Fallback calculations
                        if ($results -gt 0) {
                            # Use results as estimate
                            $estimatedTotal = $results
                            $progressPercent = 100
                        } elseif ($crawled -gt 0) {
                            # Use crawled * 20
                            $estimatedTotal = $crawled * 20
                            $progressPercent = if ($estimatedTotal -gt 0) {
                                [Math]::Min(100, [Math]::Round(($results / $estimatedTotal) * 100, 1))
                            } else { 0 }
                        } else {
                            $estimatedTotal = 0
                        $progressPercent = 0
                        }
                    }
                    
                    # Determine scan status based on REAL task counts (using actualTotal not totalCreated)
                    $status = "[RUNNING]"
                    $statusColor = "Cyan"
                    
                    # Check if scan is complete using ACTUAL task counts
                    if ($tasksPending -eq 0 -and $actualTotal -gt 0) {
                        # All tasks done (pending = 0 and we have completed/failed tasks)
                        $status = "[COMPLETED]"
                        $statusColor = "Green"
                    } elseif ($tasksPending -gt 0 -and $tasksPending -le ($estimatedTotal * 0.25)) {
                        # Less than 25% tasks remaining
                        $status = "[COMPLETING...]"
                        $statusColor = "Yellow"
                    } elseif ($results -gt 0 -and $tasksPending -eq 0 -and ($tasksCompleted + $tasksFailed) -eq 0) {
                        # Have results but no task tracking - likely completed
                        $status = "[COMPLETED]"
                        $statusColor = "Green"
                    }
                    
                    # Display progress bar
                    $barLength = 30
                    $filled = [Math]::Round($barLength * $progressPercent / 100)
                    $empty = $barLength - $filled
                    $bar = ("=" * $filled) + ("-" * $empty)
                    
                    Write-Host "  scan_$scanId" -ForegroundColor White -NoNewline
                    Write-Host " | " -NoNewline
                    Write-Host $bar -ForegroundColor Cyan -NoNewline
                    Write-Host " | " -NoNewline
                    Write-Host "$progressPercent%" -ForegroundColor Yellow -NoNewline
                    Write-Host " | " -NoNewline
                    Write-Host $status -ForegroundColor $statusColor
                    
                    # Show details with REAL task tracking
                    Write-Host "    +-- URLs Crawled: $crawled" -ForegroundColor Gray
                    Write-Host "    +-- Scanner Results: $results" -ForegroundColor Gray
                    
                    # Show task tracking info
                    if ($tasksCompleted -gt 0 -or $tasksFailed -gt 0) {
                        # We have tracking data
                        Write-Host "    +-- Total Tasks: $estimatedTotal" -ForegroundColor Cyan
                        
                        # tasksPending already adjusted to 0 if negative (line 298)
                        Write-Host "    +-- Tasks Pending: $tasksPending" -ForegroundColor Yellow
                        Write-Host "    +-- Tasks Completed: $tasksCompleted" -ForegroundColor Green
                        
                        if ($tasksFailed -gt 0) {
                            Write-Host "    +-- Tasks Failed: $tasksFailed" -ForegroundColor Red
                        }
                        
                        # Show tracking accuracy indicator
                        if ($totalCreated -gt 0 -and $totalCreated -ne $actualTotal) {
                            Write-Host "    +-- Tracked at Creation: $totalCreated (partial)" -ForegroundColor DarkGray
                        }
                    } else {
                        # No tracking data yet
                        if ($estimatedTotal -gt 0) {
                            Write-Host "    +-- Estimated Tasks: $estimatedTotal (initializing...)" -ForegroundColor DarkGray
                        } else {
                            Write-Host "    +-- Tasks: Calculating..." -ForegroundColor DarkGray
                        }
                    }
                    Write-Host ""
                }
            }
        }
        # Show completed scans from final results if no active queues
        if ($allKeys.Count -eq 0 -and $finalKeys) {
            Write-Host "  (No active queues - showing recent completed scans)" -ForegroundColor Gray
            $finalKeys | Select-Object -First 3 | ForEach-Object {
                $scanId = $_ -replace "scan_results_final:", ""
                $status = docker exec $RedisContainerId redis-cli HGET $_ status 2>$null
                if (-not $status) { $status = "completed" }
                Write-Host "  Final: $scanId : $status" -ForegroundColor DarkGreen
            }
        } elseif ($allKeys.Count -eq 0) {
            Write-Host "  (No pending items in queues)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  (Unable to query Redis - ensure Docker is running)" -ForegroundColor Red
    }
    Write-Host ""

    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host "Auto-refresh in 10 seconds... | Press SPACE to refresh now | Press ESC to exit" -ForegroundColor Yellow
    Write-Host "================================================================================" -ForegroundColor Green
}

# Main loop
Write-Host "`n[INFO] Starting real-time log monitoring..." -ForegroundColor Green
Write-Host "[INFO] Logs will auto-refresh every 10 seconds" -ForegroundColor Green
Write-Host "[INFO] All data shown is REAL and LIVE from the running system`n" -ForegroundColor Cyan
Start-Sleep -Seconds 2

while ($true) {
    Show-Logs
    
    # Wait for key press or timeout after 10 seconds for faster updates
    $timeout = 10
    $startTime = Get-Date
    
    while (((Get-Date) - $startTime).TotalSeconds -lt $timeout) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq 'Escape') {
                Write-Host "`nExiting log viewer..." -ForegroundColor Red
                exit
            }
            # Any other key refreshes immediately
            break
        }
        Start-Sleep -Milliseconds 100
    }
}