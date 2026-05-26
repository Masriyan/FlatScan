package main

import (
	"fmt"
	"io"
)

func PrintBashCompletion(w io.Writer) {
	fmt.Fprint(w, `_flatscan() {
    local cur prev words cword
    _init_completion 2>/dev/null || {
        COMPREPLY=()
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
    }

    local file_flags="-f --file --json --pdf --html --report --yara --sigma --stix --extract-ioc --ioc-allowlist --case-db"
    local dir_flags="--dir --report-pack"
    local path_flags="--rules --plugins"

    case "$prev" in
        -f|--file|--json|--pdf|--html|--report|--yara|--sigma|--stix|--extract-ioc|--ioc-allowlist|--case-db)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
        --dir|--report-pack)
            COMPREPLY=( $(compgen -d -- "$cur") )
            return 0
            ;;
        --rules|--plugins)
            COMPREPLY=( $(compgen -f -- "$cur") $(compgen -d -- "$cur") )
            return 0
            ;;
        -m|--mode)
            COMPREPLY=( $(compgen -W "quick standard deep" -- "$cur") )
            return 0
            ;;
        --report-mode)
            COMPREPLY=( $(compgen -W "Full Summary minimal" -- "$cur") )
            return 0
            ;;
        --completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") )
            return 0
            ;;
        --decode-depth)
            COMPREPLY=( $(compgen -W "0 1 2 3 4 5" -- "$cur") )
            return 0
            ;;
        --case|--min-string|--max-analyze-bytes|--max-archive-files|--max-carves|--watch-interval|--splash-seconds)
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        local all_flags="-f --file --dir -m --mode --report-mode
            --report --json --pdf --html --yara --sigma --stix
            --extract-ioc --report-pack --rules --plugins
            --ioc-allowlist --case --case-db
            --carve --decode-depth --min-string
            --max-analyze-bytes --max-archive-files --max-carves
            --external-tools --no-color --no-progress --no-splash --debug
            --watch --watch-interval --splash-seconds
            --interactive -i --shell --completion --version"
        COMPREPLY=( $(compgen -W "$all_flags" -- "$cur") )
        return 0
    fi

    COMPREPLY=( $(compgen -f -- "$cur") )
    return 0
}
complete -F _flatscan flatscan
complete -F _flatscan ./flatscan
`)
}

func PrintZshCompletion(w io.Writer) {
	fmt.Fprint(w, `#compdef flatscan

_flatscan() {
    local -a args
    args=(
        '(-f --file)'{-f,--file}'[file to scan]:file:_files'
        '--dir[scan all files in a directory]:directory:_files -/'
        '(-m --mode)'{-m,--mode}'[scan mode]:mode:(quick standard deep)'
        '--report-mode[report verbosity]:mode:(Full Summary minimal)'
        '--report[plain-text report path]:file:_files'
        '--json[JSON report path (- for stdout)]:file:_files'
        '--pdf[PDF report path]:file:_files'
        '--html[HTML analyst report path]:file:_files'
        '--yara[YARA hunting rule path]:file:_files'
        '--sigma[Sigma hunting rule path]:file:_files'
        '--stix[STIX 2.1 bundle path]:file:_files'
        '--extract-ioc[IOC text export path]:file:_files'
        '--report-pack[write all reports to directory]:directory:_files -/'
        '--rules[rule pack files or directories]:file:_files'
        '--plugins[plugin pack files or directories]:file:_files'
        '--ioc-allowlist[IOC allowlist path]:file:_files'
        '--case[case identifier]:case id: '
        '--case-db[case JSONL database path]:file:_files'
        '--decode-depth[max nested decode depth (0-5)]:depth:(0 1 2 3 4 5)'
        '--min-string[minimum string length]:length: '
        '--max-analyze-bytes[max bytes for in-memory analysis]:bytes: '
        '--max-archive-files[max archive entries to inspect]:count: '
        '--max-carves[max carved artifacts]:count: '
        '--watch-interval[watch mode poll interval in seconds]:seconds: '
        '--splash-seconds[splash duration in seconds]:seconds: '
        '--completion[print shell completion script]:shell:(bash zsh fish)'
        '--carve[enable recursive safe file carving]'
        '--external-tools[run optional external metadata tools]'
        '--no-color[disable colorized output]'
        '--no-progress[disable progress percentage]'
        '--no-splash[disable startup splash screen]'
        '--debug[enable scanner debug logs]'
        '--watch[monitor --dir for new files]'
        '(-i --interactive)'{-i,--interactive}'[launch guided interactive mode]'
        '--shell[launch manual command shell]'
        '--version[print FlatScan version]'
    )
    _arguments -s $args
}

_flatscan "$@"
`)
}

func PrintFishCompletion(w io.Writer) {
	fmt.Fprint(w, `# FlatScan fish shell completion
# Install: ./flatscan --completion fish > ~/.config/fish/completions/flatscan.fish

set -l scan_modes quick standard deep
set -l report_modes Full Summary minimal
set -l shells bash zsh fish

complete -c flatscan -s f -l file       -d 'File to scan'                    -r -F
complete -c flatscan       -l dir        -d 'Directory to scan (batch mode)'   -r -F
complete -c flatscan -s m -l mode       -d 'Scan mode'                        -r -a "$scan_modes"
complete -c flatscan       -l report-mode -d 'Report verbosity'               -r -a "$report_modes"

complete -c flatscan -l report      -d 'Plain-text report path'               -r -F
complete -c flatscan -l json        -d 'JSON report path (- for stdout)'       -r -F
complete -c flatscan -l pdf         -d 'PDF report path'                       -r -F
complete -c flatscan -l html        -d 'HTML analyst report path'              -r -F
complete -c flatscan -l yara        -d 'YARA hunting rule path'                -r -F
complete -c flatscan -l sigma       -d 'Sigma hunting rule path'               -r -F
complete -c flatscan -l stix        -d 'STIX 2.1 bundle path'                  -r -F
complete -c flatscan -l extract-ioc -d 'IOC text export path'                  -r -F
complete -c flatscan -l report-pack -d 'Directory for full report pack'        -r -F
complete -c flatscan -l rules       -d 'Rule pack files or directories'        -r -F
complete -c flatscan -l plugins     -d 'Plugin pack files or directories'      -r -F
complete -c flatscan -l ioc-allowlist -d 'IOC allowlist file'                  -r -F
complete -c flatscan -l case        -d 'Case identifier'                       -r
complete -c flatscan -l case-db     -d 'Case JSONL database path'              -r -F

complete -c flatscan -l decode-depth      -d 'Max nested decode depth (0-5)'   -r -a '0 1 2 3 4 5'
complete -c flatscan -l min-string        -d 'Minimum string length'            -r
complete -c flatscan -l max-analyze-bytes -d 'Max bytes for analysis'           -r
complete -c flatscan -l max-archive-files -d 'Max archive entries to inspect'   -r
complete -c flatscan -l max-carves        -d 'Max carved artifacts'             -r
complete -c flatscan -l watch-interval    -d 'Watch mode poll interval (sec)'   -r
complete -c flatscan -l splash-seconds    -d 'Splash duration in seconds'       -r
complete -c flatscan -l completion        -d 'Print shell completion script'    -r -a "$shells"

complete -c flatscan -l carve          -d 'Enable recursive safe file carving'
complete -c flatscan -l external-tools -d 'Run optional external metadata tools'
complete -c flatscan -l no-color       -d 'Disable colorized output'
complete -c flatscan -l no-progress    -d 'Disable progress percentage'
complete -c flatscan -l no-splash      -d 'Disable startup splash screen'
complete -c flatscan -l debug          -d 'Enable scanner debug logs'
complete -c flatscan -l watch          -d 'Monitor --dir for new files'
complete -c flatscan -s i -l interactive -d 'Launch guided interactive mode'
complete -c flatscan -l shell          -d 'Launch manual command shell'
complete -c flatscan -l version        -d 'Print FlatScan version'
`)
}
