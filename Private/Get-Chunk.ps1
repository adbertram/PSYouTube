function Get-Chunk {
    [OutputType("System.Array")]
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [int]$size = 1,

        [Parameter(ValueFromPipeline = $true)]
        $InputObject
    )

    begin {
        $buf = @()
    }

    process {
        $buf += $InputObject

        if ( $size -gt 0 ) {
            # return chunks
            $start = 0
            $end = $size - 1
            $last = $buf.Count - 1
            while ($end -le $last) {
                , $buf[$start..$end]

                $start = $end + 1
                $end += $size
            }

            # store only items to be used, release unused elements for a Garbage Collection
            if ($start -gt $last) {
                $buf = @()
            } elseif ( $start -ne 0 ) {
                $buf = $buf[$start..$last]
            }
        }
    }

    end {
        if ( $size -lt 0 ) {
            # return a reverse ordered chunks
            $start = -1
            $end = $size
            $last = - $buf.Count
            while ($end -ge $last) {
                , $buf[$start..$end]

                $start = $end - 1
                $end += $size
            }

            if ($start -lt $last) {
                $buf = @()
            } elseif ( $start -ne -1 ) {
                $buf = $buf[$start..$last]
            }
        }

        if ( $buf ) {
            , $buf
            $buf = @()  # release unused elements for a Garbage Collection
        }
    }
}