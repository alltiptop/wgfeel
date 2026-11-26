#compdef @BINARY@
# Generated adapter. Candidate output is data, never evaluated.
_@FUNCTION@() {
    local value description result=1
    local -a request values descriptions
    request=("${words[@]:1}")
    request[CURRENT-1]="$PREFIX"
    while IFS=$'\t' read -r value description; do
        case "$value" in
            @files) _files && result=0 ;;
            @directories) _files -/ && result=0 ;;
            *)
                if [[ -n "$value" ]]; then
                    values+=("$value")
                    descriptions+=("$value -- $description")
                fi
                ;;
        esac
    done < <(command "${words[1]}" _complete "$((CURRENT-2))" -- "${request[@]}" 2>/dev/null)
    if (( ${#values} )); then
        compadd -d descriptions -- "${values[@]}" && result=0
    fi
    return $result
}
compdef _@FUNCTION@ @BINARY@
# A file in fpath is first evaluated by autoload under this function name.
if [[ ${funcstack[1]} == _@BINARY@ ]]; then
    _@FUNCTION@ "$@"
fi
