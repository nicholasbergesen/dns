# Initialize an empty hashtable to store DNS query counts
$dnsCounts = @{}

# Get all log files in the current directory matching dns-*.log
$logFiles = Get-ChildItem -Filter "dns-*.log"

# Iterate over each log file
foreach ($file in $logFiles) {
    # Read the content of the log file line by line
    $lines = Get-Content $file.FullName

    # Iterate over each line in the file
    foreach ($line in $lines) {
        # Check if the line contains "Handling question for: Name:"
        if ($line -match 'Handling question for: Name: (.*?) Type:') {
            # Extract the DNS query name using regex
            $name = $matches[1]

            # Update the count for the DNS query name
            if ($dnsCounts.ContainsKey($name)) {
                $dnsCounts[$name] += 1
            } else {
                $dnsCounts[$name] = 1
            }
        }
        elseif ($line -match 'Blocked domain: (.*)') {
            # Extract the DNS query name using regex
            $blockedName = $matches[1]

            # Decrement the count for the blocked DNS query name
            if ($dnsCounts.ContainsKey($blockedName)) {
                $dnsCounts[$blockedName] -= 1
            } else {
                # Initialize with -1 if the name wasn't previously counted
                $dnsCounts[$blockedName] = -1
            }
        }
    }
}

# Output the DNS query names with their counts, sorted by count in descending order
$dnsCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Format-Table Name, Value -AutoSize
