#!/usr/bin/env bash
# ── CPIP Bash Completion (Command Line Kung Fu, p.174-176) ───────────
# Source this file: . cpip-completion.bash
# Or install: sudo cp cpip-completion.bash /etc/bash_completion.d/cpip

_cpip_completions() {
    local cur prev commands mesh_cmds ecc_cmds covert_cmds
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    commands="tui status brew pour when info 418 418-alcohol additions version whoami
              config stats mesh ecc deaddrop covert defense itf identity dns groups
              sync cluster help menu copy paste colors sysinfo watch cal stopwatch backup"

    mesh_cmds="status peers inbox send send-raw broadcast scan routes sat radio mobile queued"
    ecc_cmds="status address book resolve"
    covert_cmds="encode decode brew status"
    defense_cmds="status"
    itf_cmds="status blacklist whitelist clear stealth probe"
    identity_cmds="list show publish vouch graph"
    dns_cmds="list register resolve remove"
    groups_cmds="list create join leave send history"
    sync_cmds="channels pending send clocks request"
    cluster_cmds="start stop status connect demo help"

    # Global commands
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        return 0
    fi

    # Subcommand completions
    case "${COMP_WORDS[1]}" in
        mesh)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "$mesh_cmds" -- "$cur") )
            fi
            ;;
        ecc)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "$ecc_cmds" -- "$cur") )
            fi
            ;;
        covert)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "$covert_cmds" -- "$cur") )
            fi
            ;;
        defense)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "$defense_cmds" -- "$cur") )
            fi
            ;;
        itf)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "$itf_cmds" -- "$cur") )
            fi
            ;;
        identity)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "$identity_cmds" -- "$cur") )
            fi
            ;;
        dns)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "$dns_cmds" -- "$cur") )
            fi
            ;;
        groups)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "$groups_cmds" -- "$cur") )
            fi
            ;;
        sync)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "$sync_cmds" -- "$cur") )
            fi
            ;;
        cluster)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "$cluster_cmds" -- "$cur") )
            fi
            ;;
    esac

    return 0
}

complete -F _cpip_completions cpip
