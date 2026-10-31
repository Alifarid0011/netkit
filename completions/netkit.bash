# Source this file in Bash. Completion is deliberately offline.
_netkit_complete() {
 local current="${COMP_WORDS[COMP_CWORD]}"
 if (( COMP_CWORD == 1 )); then
   COMPREPLY=( $(compgen -W 'help version ip ports doctor probe ping proxy capture pcap firewall router tor tui' -- "$current") )
 else
   COMPREPLY=( $(compgen -W '--help --json --explain' -- "$current") )
 fi
}
complete -F _netkit_complete netkit
