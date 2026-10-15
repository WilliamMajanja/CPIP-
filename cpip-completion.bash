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
              sync cluster cell sdr radio assess intel hardware sensors field tamper
              deception modem ss7 diameter sigfw ob-channel power em-sec carrier duress
              mesh-security evidence circumvention airgap hygiene crypto pq-mesh help
              menu copy paste colors sysinfo watch cal stopwatch backup"

    mesh_cmds="status peers inbox send send-raw broadcast scan routes sat radio mobile queued threat-report intel-status attack-detect"
    ecc_cmds="status address book resolve"
    covert_cmds="encode decode brew status"
    defense_cmds="status"
    itf_cmds="status blacklist whitelist clear stealth probe"
    identity_cmds="list show publish vouch graph"
    dns_cmds="list register resolve remove"
    groups_cmds="list create join leave send history"
    sync_cmds="channels pending send clocks request"
    cluster_cmds="start stop status connect demo help"
    cell_cmds="status scan history baseline-reset"
    sdr_cmds="status scan spectrum capture"
    radio_cmds="status spectrum hop"
    assess_cmds="status explain baselines history now summary listen"
    intel_cmds="status share map risk-score verify"
    hardware_cmds="status test watchdog"
    sensors_cmds="status log calibrate"
    field_cmds="status radio-silence deadman geofence plan-sweep"
    tamper_cmds="status log test"
    deception_cmds="status chaff-intensity honeypot"
    modem_cmds="status fw-check fw-history cve-scan"
    ss7_cmds="status log"
    diameter_cmds="status"
    mesh_security_cmds="status graph peers"
    ob_channel_cmds="list select send test"
    power_cmds="status log baseline-reset"
    emsec_cmds="status scan faraday-test tempest-detect"
    carrier_cmds="status register-webhook sim-change-history"
    duress_cmds="status set-code test panic-delete"
    evidence_cmds="status chain notarize verify notarize-all"
    circumvention_cmds="status mode front"
    airgap_cmds="status qr-send qr-sync audio-tx audio-rx nfc-pair"
    hygiene_cmds="status scan monitor quarantine"
    pq_mesh_cmds="status enforce handshake"

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
        cell) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$cell_cmds" -- "$cur") ) ;;
        sdr) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$sdr_cmds" -- "$cur") ) ;;
        radio) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$radio_cmds" -- "$cur") ) ;;
        assess) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$assess_cmds" -- "$cur") ) ;;
        intel) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$intel_cmds" -- "$cur") ) ;;
        hardware) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$hardware_cmds" -- "$cur") ) ;;
        sensors) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$sensors_cmds" -- "$cur") ) ;;
        field) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$field_cmds" -- "$cur") ) ;;
        tamper) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$tamper_cmds" -- "$cur") ) ;;
        deception) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$deception_cmds" -- "$cur") ) ;;
        modem) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$modem_cmds" -- "$cur") ) ;;
        ss7) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$ss7_cmds" -- "$cur") ) ;;
        diameter) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$diameter_cmds" -- "$cur") ) ;;
        mesh-security) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$mesh_security_cmds" -- "$cur") ) ;;
        ob-channel) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$ob_channel_cmds" -- "$cur") ) ;;
        power) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$power_cmds" -- "$cur") ) ;;
        em-sec) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$emsec_cmds" -- "$cur") ) ;;
        carrier) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$carrier_cmds" -- "$cur") ) ;;
        duress) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$duress_cmds" -- "$cur") ) ;;
        evidence) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$evidence_cmds" -- "$cur") ) ;;
        circumvention) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$circumvention_cmds" -- "$cur") ) ;;
        airgap) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$airgap_cmds" -- "$cur") ) ;;
        hygiene) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$hygiene_cmds" -- "$cur") ) ;;
        pq-mesh) [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=( $(compgen -W "$pq_mesh_cmds" -- "$cur") ) ;;
        crypto)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "status pqc-status pqc-keys pqc-rotate pqc-handshake pq-mesh" -- "$cur") )
            elif [ "${COMP_WORDS[2]}" = "pq-mesh" ] && [ "$COMP_CWORD" -eq 3 ]; then
                COMPREPLY=( $(compgen -W "$pq_mesh_cmds" -- "$cur") )
            fi
            ;;
    esac

    return 0
}

complete -F _cpip_completions cpip
