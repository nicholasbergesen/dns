$dnsCounts = @{}
$logFiles = Get-ChildItem -Filter "dns-*.log"

foreach ($file in $logFiles) {
    $lines = Get-Content $file.FullName

    foreach ($line in $lines) {
        if ($line -match 'Handling question for: Name: (.*?) Type:') {
            $name = $matches[1]

            if ($dnsCounts.ContainsKey($name)) {
                $dnsCounts[$name] += 1
            } else {
                $dnsCounts[$name] = 1
            }
        }
        elseif ($line -match 'Blocked domain: (.*)') {
            $blockedName = $matches[1]

            if ($dnsCounts.ContainsKey($blockedName)) {
                $dnsCounts[$blockedName] -= 1
            } else {
                $dnsCounts[$blockedName] = -1
            }
        }
    }
}

$dnsCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Format-Table Name, Value -AutoSize
