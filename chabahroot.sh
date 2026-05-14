#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
CHABAHROOT_DIR="$PROJECT_ROOT/chabahroot"

TRACEFS_PATH="/sys/kernel/tracing"
EVENTS_FILE="$TRACEFS_PATH/trace_pipe"
ENABLED_EVENTS_FILE="/tmp/chabah_enabled_events"
LIVE_EVENT_STREAM=""
M1_TRACER_PID=""
TEMP_DIR_CHABAH=""  

SAMPLE_EVENTS="$PROJECT_ROOT/examples/sample_events.ndjson"
DETECTION_RULES="$CHABAHROOT_DIR/vigie_comportementale/detection_rules.json"
DETECTION_STATE_DIR="/tmp/chabah_detection_state"
ALERTS_FILE="$DETECTION_STATE_DIR/alerts.ndjson"
ACTIONS_LOG="$DETECTION_STATE_DIR/actions.log"
SEEN_PIDS_FILE="$PROJECT_ROOT/detection/tmp/seen_pids.tmp"

LOG_DIR="/var/log/chabahroot"
LOG_FILE="$LOG_DIR/history.log"
CURRENT_USER="${USER:-$(id -un 2>/dev/null || echo root)}"

# Codes de sortie stables les appelants externes peuvent brancher dessus sans parser le texte
ERR_UNKNOWN_OPTION=100
ERR_MISSING_PARAM=101
ERR_MISSING_FILE=102
ERR_NO_PRIVILEGE=103
ERR_MISSING_CMD=104
ERR_TRACEFS=105
TRACEPOINTS=(
    "syscalls/sys_enter_execve"
    "syscalls/sys_enter_setuid"
    "syscalls/sys_enter_setgid"
    "syscalls/sys_enter_prctl"
)
EXEC_MODE="sequential"
INPUT_MODE="auto"
INPUT_FILE=""
RUN_MODE="full"
DEFENSIVE_PID=""
LIVE_CAPTURE_ACTIVE="0"
#Format tableau JSON les mots-cles contenant un espace seraient mal decoupes par split(" ")
SENSITIVE_KEYWORDS='["pass","password","token","secret","key"]'
TARGET_UID="0"
POLL_INTERVAL="2"

DETECTION_RULES_CACHE="" # Cache des regles charge une seule fois au demarrage; evite une lecture disque par evenement traite

load_rules_conf() {
    if [[ -f "$CHABAHROOT_DIR/socle_commun/rules.conf" ]]; then
        source "$CHABAHROOT_DIR/socle_commun/rules.conf" || true
    fi
}

ensure_log_dir() {
    [[ -d "$LOG_DIR" ]] && { touch "$LOG_FILE" 2>/dev/null || true; return 0; }
    mkdir -p "$LOG_DIR" 2>/dev/null || return 1
    touch "$LOG_FILE" 2>/dev/null || return 1
}

log_line() {
    local level="$1"
    local category="$2"
    local message="$3"
    local file_level ts

    printf '[%s] [%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$category" "$message" >&2
    case "$level" in
        INFO|SUCCESS) file_level="INFOS" ;;
        # Chaque niveau est conserve tel quel dans le fichier l'ecrasement precedent en ERROR
        #effacait la distinction entre avertissement operationnel et alerte de securite
        WARN)         file_level="WARN"  ;;
        ALERT)        file_level="ALERT" ;;
        *)            file_level="ERROR" ;;
    esac

    ts="$(date '+%Y-%m-%d-%H-%M-%S')"
    # Le fichier peut ne pas encore exister si ensure_log_dir n'a pas tourne on ne bloque pas le flux pour ca
    [[ -w "$LOG_FILE" ]] && \
        printf '%s : %s : %s : [%s] %s\n' "$ts" "$CURRENT_USER" "$file_level" "$category" "$message" >> "$LOG_FILE"
}
log_info()    { log_line "INFO"    "$1" "$2"; }
log_warn()    { log_line "WARN"    "$1" "$2"; }
log_error()   { log_line "ERROR"   "$1" "$2"; }
log_alert()   { log_line "ALERT"   "$1" "$2"; }
log_success() { log_line "SUCCESS" "$1" "$2"; }
log_section() { printf '[%s] [SECTION] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >&2; }


verify_root() {
    [[ "$EUID" -eq 0 ]] && return 0
    log_error "SYSTEM" "This action requires root privileges"
    return 1
}

require_command() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || {
        log_error "SYSTEM" "Missing required command: $cmd"
        return 1
    }
}

read_status_value() {
    local pid="$1"
    local key="$2"
    awk -v target="$key" '$1 == target ":" { print $2; exit }' "/proc/$pid/status" 2>/dev/null || true
}

m1_check_prerequisites() {
    local tracepoint

    verify_root || return 1

    [[ -d "$TRACEFS_PATH" ]] || {
        log_error "M1" "tracefs is not mounted at $TRACEFS_PATH"
        return 1
    }

    for tracepoint in "${TRACEPOINTS[@]}"; do
        [[ -e "$TRACEFS_PATH/events/$tracepoint/enable" ]] || {
            log_error "M1" "Missing tracepoint: $tracepoint"
            return 1
        }
    done

    log_success "M1" "M1 prerequisites are valid"
}

m1_enable_tracepoints() {
    local tracepoint

    log_info "M1" "Enabling tracepoints for execve, setuid, setgid, and prctl"

    # tracefs peut garder un etat partiel d un essai precedent; on coupe avant de retoucher les hooks.
    echo 0 > "$TRACEFS_PATH/tracing_on" 2>/dev/null || {
        log_error "M1" "Cannot write to tracefs"
        return 1
    }

    : > "$TRACEFS_PATH/trace" 2>/dev/null || true

    for tracepoint in "${TRACEPOINTS[@]}"; do
        echo 1 > "$TRACEFS_PATH/events/$tracepoint/enable" 2>/dev/null || {
            log_warn "M1" "Could not enable $tracepoint"
            continue
        }
    done

    printf '%s\n' "${TRACEPOINTS[@]}" > "$ENABLED_EVENTS_FILE"
    echo 1 > "$TRACEFS_PATH/tracing_on"
    log_success "M1" "Tracepoints enabled"
}

m1_parse_trace_event() {
    local line="$1"
    local comm pid syscall argv uid gid ppid event_type

    # Le prefixe avant sys_enter_* varie selon le scheduler on isole seulement nom, pid et syscall
    if [[ ! "$line" =~ ^[[:space:]]*([^[:space:]-]+)-([0-9]+).*[[:space:]]sys_enter_([a-z_]+): ]]; then
        return 1
    fi

    comm="${BASH_REMATCH[1]}"
    pid="${BASH_REMATCH[2]}"
    syscall="${BASH_REMATCH[3]}"
    argv=""

    case "$syscall" in
        execve)
            [[ "$line" =~ filename=\"?([^\",[:space:]]+) ]] && argv="${BASH_REMATCH[1]}"
            event_type=1
            ;;
        setuid)
            [[ "$line" =~ uid=([0-9]+) ]] && argv="setuid(${BASH_REMATCH[1]})"
            event_type=2
            ;;
        setgid)
            [[ "$line" =~ gid=([0-9]+) ]] && argv="setgid(${BASH_REMATCH[1]})"
            event_type=3
            ;;
        prctl)
            [[ "$line" =~ option=([0-9]+) ]] && argv="prctl(option=${BASH_REMATCH[1]})"
            event_type=4
            ;;
        *)
            return 1
            ;;
    esac

    uid="$(read_status_value "$pid" "Uid")"
    gid="$(read_status_value "$pid" "Gid")"
    ppid="$(read_status_value "$pid" "PPid")"

    # Le processus peut deja avoir disparu le pipeline aval attend tout de meme une forme stable
    
    #65534 remplace 0 comme valeur par defaut pour uid et gid -> un processus disparu

    #ne doit pas etre confondu avec root par les regles de detection

    uid="${uid:-65534}"
    gid="${gid:-65534}"
    ppid="${ppid:-1}"
    printf 'pid=%s ppid=%s uid=%s gid=%s ts=%s comm=%s argv=%s event_type=%s\n' \
        "$pid" "$ppid" "$uid" "$gid" "$(date +%s%N)" "$comm" "$argv" "$event_type"
}

m1_stream_events() {
    local line

    [[ -r "$EVENTS_FILE" ]] || {
        log_error "M1" "trace_pipe is not readable: $EVENTS_FILE"
        return 1
    }

    log_info "M1" "Streaming events from tracefs"

    while IFS= read -r line; do
        [[ "$line" =~ sys_enter_(execve|setuid|setgid|prctl) ]] || continue
        m1_parse_trace_event "$line" || true
    done < "$EVENTS_FILE"
}

m1_disable_tracepoints() {
    local tracepoint

    if [[ -f "$ENABLED_EVENTS_FILE" ]]; then
        while IFS= read -r tracepoint; do
            [[ -n "$tracepoint" ]] || continue
            echo 0 > "$TRACEFS_PATH/events/$tracepoint/enable" 2>/dev/null || true
        done < "$ENABLED_EVENTS_FILE"
    fi

    echo 0 > "$TRACEFS_PATH/tracing_on" 2>/dev/null || true
    rm -f "$ENABLED_EVENTS_FILE"
    log_success "M1" "Tracepoints disabled"
}

m1_capture_start() {
    m1_check_prerequisites || return 1
    m1_enable_tracepoints || return 1
    
    TEMP_DIR_CHABAH="$(mktemp -d /tmp/chabah.XXXXXX)" || {
        log_error "M1" "Cannot create secure temporary directory"
        return 1
    }
    LIVE_EVENT_STREAM="$TEMP_DIR_CHABAH/kernel_events.pipe"
    M1_TRACER_PID="$TEMP_DIR_CHABAH/tracer.pid"
    
    [[ "$(stat -c '%a' "$TEMP_DIR_CHABAH" 2>/dev/null)" == "700" ]] || {
        log_error "M1" "Secure directory has unexpected permissions"
        rm -rf "$TEMP_DIR_CHABAH"
        return 1
    }
    
    : > "$LIVE_EVENT_STREAM" #null command cette commande tronque le contenu de $LIVE_EVENT_STREAM
    
    # Le meme fichier recoit stderr pour ne pas perdre une panne noyau qui casserait un essai hors terminal
    m1_stream_events >> "$LIVE_EVENT_STREAM" 2>>"$LIVE_EVENT_STREAM" &
    echo "$!" > "$M1_TRACER_PID"
    log_success "M1" "Tracer started with PID=$! (secure: $TEMP_DIR_CHABAH)"
}

m1_capture_stop() {
    local tracer_pid=""

    if [[ -n "$M1_TRACER_PID" && -f "$M1_TRACER_PID" ]]; then
        tracer_pid="$(cat "$M1_TRACER_PID" 2>/dev/null || true)"
        [[ -n "$tracer_pid" ]] && kill "$tracer_pid" 2>/dev/null || true
        rm -f "$M1_TRACER_PID"
    fi

    m1_disable_tracepoints
    
    if [[ -n "$TEMP_DIR_CHABAH" && -d "$TEMP_DIR_CHABAH" ]]; then
        rm -rf "$TEMP_DIR_CHABAH" || log_warn "M1" "Could not remove secure temp directory"
        TEMP_DIR_CHABAH=""
        LIVE_EVENT_STREAM=""
    fi
}

m1_capture_status() {
    local tracepoint enabled tracer_pid=""

    if [[ -f "$M1_TRACER_PID" ]]; then
        tracer_pid="$(cat "$M1_TRACER_PID" 2>/dev/null || true)"
    fi

    if [[ -n "$tracer_pid" ]] && kill -0 "$tracer_pid" 2>/dev/null; then
        log_success "M1" "Tracer active with PID=$tracer_pid"
    else
        log_info "M1" "Tracer is not running"
    fi

    for tracepoint in "${TRACEPOINTS[@]}"; do
        enabled="$(cat "$TRACEFS_PATH/events/$tracepoint/enable" 2>/dev/null || echo "0")"
        log_info "M1" "$tracepoint enabled=$enabled"
    done
}

m3_parse_raw_event() {
    local raw_event="$1"
    local pid ppid uid gid ts comm argv event_type

    # Le format plat reste ici pour coller a M1 et aux corpus d'essai deja poses sur disque

    if [[ "$raw_event" =~ pid=([0-9]+)[[:space:]]+ppid=([0-9]+)[[:space:]]+uid=([0-9]+)[[:space:]]+gid=([0-9]+)[[:space:]]+ts=([0-9]+)[[:space:]]+comm=([^[:space:]]+)[[:space:]]+argv=(.+)[[:space:]]+event_type=([0-9]+)$ ]]; then
        pid="${BASH_REMATCH[1]}"
        ppid="${BASH_REMATCH[2]}"
        uid="${BASH_REMATCH[3]}"
        gid="${BASH_REMATCH[4]}"
        ts="${BASH_REMATCH[5]}"
        comm="${BASH_REMATCH[6]}"
        argv="${BASH_REMATCH[7]}"
        event_type="${BASH_REMATCH[8]}"
    else
        return 1
    fi

    case "$event_type" in
        1) event_type="exec" ;;
        2) event_type="setuid" ;;
        3) event_type="setgid" ;;
        4) event_type="prctl_caps" ;;
        *) event_type="unknown" ;;
    esac

    jq -cn \
        --argjson pid "$pid" \
        --argjson ppid "$ppid" \
        --argjson uid "$uid" \
        --argjson gid "$gid" \
        --argjson ts "$ts" \
        --arg comm "$comm" \
        --arg argv "$argv" \
        --arg event_type "$event_type" \
        '{
            timestamp: ($ts / 1000000000 | floor),
            timestamp_ns: $ts,
            event_type: $event_type,
            process: {
                pid: $pid,
                ppid: $ppid,
                comm: $comm
            },
            credentials: {
                uid: $uid,
                gid: $gid
            },
            data: {
                argv: $argv
            }
        }'
}

m3_ensure_normalized_shape() {
    local json="$1"

    echo "$json" | jq -c '
        {
            timestamp: (.timestamp // ((.timestamp_ns // 0) / 1000000000 | floor)),
            timestamp_ns: (.timestamp_ns // (.timestamp * 1000000000)),
            event_type: (.event_type // "unknown"),
            process: {
                pid: (.process.pid // 0),
                ppid: (.process.ppid // 0),
                comm: (.process.comm // "unknown"),
                cmdline: (.process.cmdline // "")
            },
            credentials: {
                uid: (.credentials.uid // 0),
                gid: (.credentials.gid // 0)
            },
            data: {
                argv: (.data.argv // "")
            }
        }'
}

m3_enrich_event_with_parent_context() {
    local json="$1"
    local ppid parent_comm parent_cmdline

    ppid="$(echo "$json" | jq -r '.process.ppid // 0')"

    if [[ "$ppid" =~ ^[0-9]+$ ]] && [[ "$ppid" -gt 0 ]]; then
        if [[ -r "/proc/$ppid/comm" ]]; then
            parent_comm="$(tr -d '\n' < "/proc/$ppid/comm" 2>/dev/null || true)"
        else
            parent_comm="unknown"
        fi

        if [[ -r "/proc/$ppid/cmdline" ]]; then
            parent_cmdline="$(tr '\0' ' ' < "/proc/$ppid/cmdline" 2>/dev/null || true)"
        else
            parent_cmdline=""
        fi
    else
        parent_comm="unknown"
        parent_cmdline=""
    fi

    echo "$json" | jq -c --arg pcomm "$parent_comm" --arg pcmd "$parent_cmdline" '
        .process.parent_comm = (if $pcomm == "" then "unknown" else $pcomm end)
        | .process.parent_cmdline = $pcmd'
}

m3_filter_sensitive_data() {
    local json="$1"

    # On remplace tout le champ argv des qu un mot sensible apparait le detail est moins important que la non fuite
    # --argjson remplace --arg pour accepter le tableau JSON natif les champs cmdline et parent_cmdline
    #sont desormais aussi filtres car ils peuvent exposer des secrets passes en arguments de processus parent
    
    echo "$json" | jq -c --argjson keywords "$SENSITIVE_KEYWORDS" '
        def redact_field(f):
            f |= (
                if . == null then ""
                else
                    reduce $keywords[] as $item (.;
                        if $item == "" then .
                        elif test($item; "i") then "[REDACTED]"
                        else .
                        end
                    )
                end
            );
        redact_field(.data.argv)
        | redact_field(.process.cmdline)
        | redact_field(.process.parent_cmdline)'
}

m3_normalize_for_output() {
    local json="$1"

    echo "$json" | jq -c '
        .normalized_at = (now | floor)
        | .source = (.source // "chaines_d_ecoute")'
}

m3_decode_event_line() {
    local line="$1"
    local parsed

    [[ -z "${line// }" ]] && return 1

    # Un seul appel jq valide et capture le JSON en meme temps l original lancait deux sous-processus
    # distincts: un premier pour verifier la validite sortie jetee et un second pour normaliser
    if parsed="$(jq -c '.' 2>/dev/null <<< "$line")"; then
        m3_ensure_normalized_shape "$parsed"
        return 0
    fi

    m3_parse_raw_event "$line"
}

m3_process_stream() {
    local source_label="$1"
    local line decoded enriched filtered normalized

    log_info "M3" "Reading event stream from $source_label"

    while IFS= read -r line; do
        decoded="$(m3_decode_event_line "$line")" || {
            log_warn "M3" "Dropping unparsable event"
            continue
        }

        enriched="$(m3_enrich_event_with_parent_context "$decoded")"
        filtered="$(m3_filter_sensitive_data "$enriched")"
        normalized="$(m3_normalize_for_output "$filtered")"
        echo "$normalized"
    done
}

m3_stream_source() {
    local input_mode="$1"
    local input_file="$2"

    case "$input_mode" in
        sample)
            [[ -f "$SAMPLE_EVENTS" ]] || {
                log_error "M3" "Sample file is missing: $SAMPLE_EVENTS"
                return 1
            }
            cat "$SAMPLE_EVENTS"
            ;;
        stdin)
            cat
            ;;
        file)
            [[ -f "$input_file" ]] || {
                log_error "M3" "Input file is missing: $input_file"
                return 1
            }
            cat "$input_file"
            ;;
        auto)
            # L'ordre suit les scripts maintenus: source explicite, relais vivant,puis corpus d'essai
            if [[ -n "${CHABAH_EVENT_SOURCE:-}" ]]; then
                [[ -e "$CHABAH_EVENT_SOURCE" ]] || {
                    log_error "M3" "CHABAH_EVENT_SOURCE is missing: $CHABAH_EVENT_SOURCE"
                    return 1
                }
                cat "$CHABAH_EVENT_SOURCE"
            elif [[ -n "$LIVE_EVENT_STREAM" && -e "$LIVE_EVENT_STREAM" ]]; then
                cat "$LIVE_EVENT_STREAM"
            else
                [[ -f "$SAMPLE_EVENTS" ]] || {
                    log_error "M3" "No event source is available"
                    return 1
                }
                log_warn "M3" "CRITICAL: Auto mode falling back to sample data (test events). Real monitoring may not be active!"
                cat "$SAMPLE_EVENTS"
            fi
            ;;
        live)
            m1_check_prerequisites || return 1
            m1_enable_tracepoints || return 1
            LIVE_CAPTURE_ACTIVE="1"
            m1_stream_events
            ;;
        *)
            log_error "M3" "Unknown input mode: $input_mode"
            return 1
            ;;
    esac
}

m3_normalize_events() {
    local input_mode="$1"
    local input_file="$2"
    local source_label="$input_mode"

    if [[ "$input_mode" == "file" ]]; then
        source_label="$input_file"
    fi
    if [[ "$input_mode" == "auto" && -n "${CHABAH_EVENT_SOURCE:-}" ]]; then
        source_label="$CHABAH_EVENT_SOURCE"
    elif [[ "$input_mode" == "auto" && -e "$LIVE_EVENT_STREAM" ]]; then
        source_label="$LIVE_EVENT_STREAM"
    elif [[ "$input_mode" == "auto" ]]; then
        source_label="$SAMPLE_EVENTS"
    fi

    m3_stream_source "$input_mode" "$input_file" | m3_process_stream "$source_label"
}

m2_prepare_detection_state() {
    mkdir -p "$DETECTION_STATE_DIR"
    touch "$ALERTS_FILE" "$ACTIONS_LOG"
}

m2_load_detection_rules() {
    [[ -f "$DETECTION_RULES" ]] || {
        log_alert "RULES" "Missing rules file: $DETECTION_RULES"
        return 1
    }

    jq empty "$DETECTION_RULES" >/dev/null 2>&1 || {
        log_error "RULES" "Invalid JSON in $DETECTION_RULES"
        return 1
    }

    # Le contenu est mis en cache ici une seule fois m2_apply_all_rules n'a plus besoin
    # de relire le fichier sur disque pour chaque evenement normalise qui traverse le pipeline

    DETECTION_RULES_CACHE="$(cat "$DETECTION_RULES")"
    log_info "RULES" "Loaded rules from $DETECTION_RULES"
}

m2_build_alert_json() {
    local rule_json="$1"
    local event_json="$2"

    jq -cn \
        --arg alert_id "$(uuidgen 2>/dev/null || printf '%04x%04x-%04x-4%03x-%04x-%04x%04x%04x' \
            $RANDOM $RANDOM $RANDOM $((RANDOM & 0x0fff)) \
            $((RANDOM & 0x3fff | 0x8000)) \
            $RANDOM $RANDOM $RANDOM)" \
        --argjson rule "$rule_json" \
        --argjson event "$event_json" \
        --argjson created_at "$(date '+%s')" \
        '{
            alert_id: $alert_id,
            timestamp: $created_at,
            rule: {
                id: $rule.id,
                name: $rule.name,
                type: $rule.type,
                severity: $rule.severity
            },
            event: $event
        }'
}

m2_execute_alert_actions() {
    local rule_json="$1"
    local alert_json="$2"
    local action

    while IFS= read -r action; do
        [[ -n "$action" ]] || continue

        case "$action" in
            journal)
                printf '%s\n' "$alert_json" >> "$ACTIONS_LOG"
                ;;
            email)
                log_info "ACTIONS" "Email action is not implemented"
                ;;
            slack)
                log_info "ACTIONS" "Slack action is not implemented"
                ;;
            *)
                log_warn "ACTIONS" "Unknown action: $action"
                ;;
        esac
    done < <(echo "$rule_json" | jq -r '.actions[]?')
}

m2_generate_alert() {
    local rule_json="$1"
    local event_json="$2"
    local alert_json rule_id rule_name severity

    rule_id="$(echo "$rule_json" | jq -r '.id')"
    rule_name="$(echo "$rule_json" | jq -r '.name')"
    severity="$(echo "$rule_json" | jq -r '.severity')"
    alert_json="$(m2_build_alert_json "$rule_json" "$event_json")"

    printf '%s\n' "$alert_json" >> "$ALERTS_FILE"
    log_alert "RULES" "Alerte [$rule_id] $rule_name (severite: $severity)"
    m2_execute_alert_actions "$rule_json" "$alert_json"
}

m2_validate_condition() {
    local condition="$1"

    #whatis jq       
    #jq (1)  - Command-line JSON processor
    
    #Une condition issue d'un fichier de regles falsifie peut devenir une injection jq
    #cette liste bloque les builtins qui interagissent avec l'environnement ou le systeme de fichiers
    
    if echo "$condition" | grep -qE '\b(env|path|input|inputs|debug|modulemeta|builtins|limit|until|recurse_down|walk|getpath|setpath|leaf_paths)\b'; then
        return 1
    fi
    return 0
}

m2_evaluate_rule() {

    local rule_json="$1"
    local event_json="$2"
    local enabled condition

    enabled="$(echo "$rule_json" | jq -r '.enabled // true')"
    [[ "$enabled" == "true" ]] || return 1

    condition="$(echo "$rule_json" | jq -r '.condition // empty')"
    [[ -n "$condition" ]] || return 1

    #la condition est validee avant execution un rules.json altere ne doit pas pouvoir
    # executer des appels jq arbitraires avec acces a lenvironnement du processus
    m2_validate_condition "$condition" || {
        log_warn "RULES" "Condition refusee (appel interdit detecte): $condition"
        return 1
    }

    if jq -e "$condition" >/dev/null 2>&1 <<< "$event_json"; then
        m2_generate_alert "$rule_json" "$event_json"
        return 0
    fi

    return 1
}

m2_apply_all_rules() {

    local event_json="$1"
    local rule_json

    # Le cache charge par m2_load_detection_rules est utilise ici plus de lecture disque par evenement
    while IFS= read -r rule_json; do
        [[ -n "$rule_json" ]] || continue
        m2_evaluate_rule "$rule_json" "$event_json" || true
    done < <(echo "$DETECTION_RULES_CACHE" | jq -c '.rules[]')
}

m2_apply_detection_rules() {

    local event_json

    log_info "DETECTION" "M2 rules engine started"

    while IFS= read -r event_json; do
        [[ -n "${event_json// }" ]] || continue

        if ! jq empty >/dev/null 2>&1 <<< "$event_json"; then
            log_warn "DETECTION" "Dropping invalid JSON event"
            continue
        fi


        m2_apply_all_rules "$event_json"
    done
}

defensive_init() {

    mkdir -p "$(dirname "$SEEN_PIDS_FILE")"
    touch "$SEEN_PIDS_FILE" 2>/dev/null || log_warn "DEFENSIVE" "Could not create PID state file"
    log_info "DEFENSIVE" "Target UID=$TARGET_UID poll=${POLL_INTERVAL}s"
}

check_suspicious_process() {
    local cmd="$1"
    local suspect

    for suspect in nc ncat netcat bash sh perl python ruby curl wget; do
        if [[ "$cmd" == "$suspect"* ]]; then
            log_alert "DEFENSIVE" "Suspicious process detected: $cmd"
            break
        fi
    done
}

prune_seen_pids() {
    local pid
    local live=()
    # Les PID Linux sont recycles; sans elagage, un PID reutilise par un nouveau processus
    # root serait ignore silencieusement parce qu il figure deja dans le fichier.
    # Seuls les PID dont /proc/$pid existe encore sont conserves.
    while IFS= read -r pid; do
        [[ -n "$pid" ]] || continue
        [[ -d "/proc/$pid" ]] && live+=("$pid")
    done < "$SEEN_PIDS_FILE"
    printf '%s\n' "${live[@]+"${live[@]}"}" > "$SEEN_PIDS_FILE" 2>/dev/null || true
}

detect_uid_escalation() {

    local uid pid ppid cmd msg

    while read -r uid pid ppid cmd; do
        [[ "$uid" -eq "$TARGET_UID" ]] || continue

        if grep -q "^${pid}$" "$SEEN_PIDS_FILE" 2>/dev/null; then
            continue
        fi

        echo "$pid" >> "$SEEN_PIDS_FILE"
        msg="Elevation detected: PID=$pid PPID=$ppid CMD=$cmd"
        log_alert "DEFENSIVE" "$msg"
        check_suspicious_process "$cmd"
    done < <(ps -eo uid=,pid=,ppid=,comm= 2>/dev/null)
}

run_defensive_cycle() {
    # L'elagage precede la detection pour que les PID recycles ne soient pas sautes au tour courant.
    prune_seen_pids
    detect_uid_escalation
}

start_defensive_background() {
    (
        defensive_init

        while true; do
            run_defensive_cycle
            sleep "$POLL_INTERVAL"
        done
    ) &

    DEFENSIVE_PID="$!"
    log_info "SYSTEM" "Defensive monitor started with PID=$DEFENSIVE_PID"
}

run_offensive_audit() {
    local whitelist binary bin_name line file

    log_warn "OFFENSIVE" "Audit mode reads host state only"
    log_info "OFFENSIVE" "Scanning SUID binaries"

    whitelist="sudo su passwd ping mount umount newgrp chsh chfn"

    while IFS= read -r binary; do
        bin_name="$(basename "$binary")"
        if [[ ! " $whitelist " =~ [[:space:]]$bin_name[[:space:]] ]]; then
            log_alert "OFFENSIVE" "Non standard SUID binary: $binary"
        fi
    done < <(find /usr /bin /sbin /tmp /opt -perm -4000 -type f 2>/dev/null)

    log_info "OFFENSIVE" "Scanning world writable files in critical paths"
    while IFS= read -r file; do
        log_alert "OFFENSIVE" "World writable file in critical path: $file"
    done < <(find /etc /usr/bin /usr/sbin /bin /sbin -perm -0002 -type f 2>/dev/null)

    log_info "OFFENSIVE" "Scanning sudoers configuration"
    if [[ -r /etc/sudoers ]]; then
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue

            if grep -qi "NOPASSWD" <<< "$line"; then
                log_alert "OFFENSIVE" "Risky sudoers rule: $line"
            fi

            if grep -qi "ALL=(ALL)" <<< "$line"; then
                log_alert "OFFENSIVE" "Broad sudoers rule: $line"
            fi
        done < /etc/sudoers
    else
        log_warn "OFFENSIVE" "sudoers is not readable"
    fi
}

run_normalized_stream() {
    m3_normalize_events "$INPUT_MODE" "$INPUT_FILE"
}

run_pipeline_sequential() {
    run_normalized_stream | m2_apply_detection_rules
}

run_pipeline_fork() {
    local fifo="/tmp/chabahroot_$$.pipe"
    local producer_pid=""
    local producer_exit=0

    # Le fifo garde le couplage faible entre normalisation et detection sans stocker tout le flux en memoire
    mkfifo "$fifo"
    run_normalized_stream > "$fifo" &
    producer_pid="$!"
    m2_apply_detection_rules < "$fifo"

    # Le code de sortie du producteur est verifie explicitement; un echec silencieux ici
    # laissait croire a une execution reussie alors que la normalisation avait plante

    wait "$producer_pid" || producer_exit="$?"
    rm -f "$fifo"
    if [[ "$producer_exit" -ne 0 ]]; then
        log_error "M4" "Le producteur a termine avec le code $producer_exit"
        return "$producer_exit"
    fi
}

run_pipeline_subshell() {
    (
        set -o pipefail
        run_normalized_stream | m2_apply_detection_rules
    )
}

run_pipeline() {
    case "$EXEC_MODE" in
        sequential)
            run_pipeline_sequential
            ;;
        fork)
            run_pipeline_fork
            ;;
        thread)
            log_info "M4" "Thread mode falls back to sequential execution in the unified path"
            run_pipeline_sequential
            ;;
        subshell)
            run_pipeline_subshell
            ;;
        *)
            log_error "M4" "Unknown execution mode: $EXEC_MODE"
            return 1
            ;;
    esac
}

restore_defaults() {

    verify_root || exit $ERR_NO_PRIVILEGE  # -r touche tracefs et des fichiers systeme root est non negociable ici

    m1_capture_stop 2>/dev/null || true

    if [[ -n "$ENABLED_EVENTS_FILE" && -f "$ENABLED_EVENTS_FILE" ]]; then
        rm -f "$ENABLED_EVENTS_FILE" || log_warn "SYSTEM" "Could not remove $ENABLED_EVENTS_FILE"
    fi
    
    if [[ -n "$TEMP_DIR_CHABAH" && -d "$TEMP_DIR_CHABAH" ]]; then
        rm -rf "$TEMP_DIR_CHABAH" || log_warn "SYSTEM" "Could not remove $TEMP_DIR_CHABAH"
    fi
    
    if [[ -d "$DETECTION_STATE_DIR" ]]; then
        rm -rf "$DETECTION_STATE_DIR" || log_warn "SYSTEM" "Could not remove $DETECTION_STATE_DIR"
    fi
    
    if [[ -n "$SEEN_PIDS_FILE" && -f "$SEEN_PIDS_FILE" ]]; then
        rm -f "$SEEN_PIDS_FILE" || log_warn "SYSTEM" "Could not remove $SEEN_PIDS_FILE"
    fi

    # On ne touche pas au fichier de log l'historique d une session reinitiali see reste utile
    EXEC_MODE="sequential"
    INPUT_MODE="auto"
    INPUT_FILE=""
    RUN_MODE="full"
    DEFENSIVE_PID=""
    LIVE_CAPTURE_ACTIVE="0"
    TEMP_DIR_CHABAH=""
    LIVE_EVENT_STREAM=""
    M1_TRACER_PID=""

    log_success "SYSTEM" "Etat transitoire reinitialise"
}

cleanup_runtime() {
    if [[ -n "$DEFENSIVE_PID" ]] && kill -0 "$DEFENSIVE_PID" 2>/dev/null; then
        kill "$DEFENSIVE_PID" 2>/dev/null || true
        wait "$DEFENSIVE_PID" 2>/dev/null || true
    fi

    # Appel inconditionnel: les tracepoints peuvent avoir ete actives via capture-start
    # dans une session anterieure sans que LIVE_CAPTURE_ACTIVE soit a 1 dans ce shell
    # m1_disable_tracepoints est idempotent et gere l'absence de tracefs proprement
    m1_disable_tracepoints 2>/dev/null || true
    
    if [[ -n "$TEMP_DIR_CHABAH" && -d "$TEMP_DIR_CHABAH" ]]; then
        rm -rf "$TEMP_DIR_CHABAH" 2>/dev/null || true
    fi
}

check_prerequisites() {
    local cmd

    # bash est retire de la liste: le script est deja en cours d execution dans bash,
    # verifier sa presence dans PATH est redondant et ne detecte aucune vraie anomalie.
    for cmd in jq ps find; do
        require_command "$cmd" || exit $ERR_MISSING_CMD
    done

    [[ -f "$DETECTION_RULES" ]] || {
        log_alert "SYSTEM" "Missing module data: $DETECTION_RULES"
        exit $ERR_MISSING_FILE
    }
}

show_help() {
    cat <<'EOF'
Usage:
  chabahroot [options] [mode] [source]
  chabahroot [sequential|fork|subshell] [sample|stdin|live|auto]
  chabahroot [sequential|fork|subshell] file <path>
  chabahroot capture-start | capture-stop | capture-status

Options:
  -h            Affiche cette aide
  -f            Execution par fork (sous-processus via fifo)
  -t            Execution par thread (retombe sur sequential en bash pur)
  -s            Execution dans un sous-shell isole
  -l <dir>      Repertoire de journalisation (defaut: /var/log/chabahroot)
  -r            Reinitialise l etat transitoire et tracefs  [root requis]

Modes d execution (positionnels ou via options courtes):
  sequential    Pipeline dans le shell courant (defaut)
  fork          Pipeline via fifo et sous-processus
  thread        Alias sequential dans ce contexte
  subshell      Pipeline dans un sous-shell

Sources d evenements:
  sample        Corpus d exemples embarque
  stdin         Lecture depuis l entree standard
  live          Capture directe tracefs              [root requis]
  auto          Detection automatique de la source (defaut - WARN: peut basculer sur sample)
  file <path>   Fichier NDJSON specifique
  --input <p>   Equivalent long de file

Sous-commandes de capture:
  capture-start    Active les tracepoints et demarre le captureur
  capture-stop     Arrete le captureur et desactive les tracepoints
  capture-status   Affiche l etat courant du captureur

Filtres d analyse:
  --pipeline-only  Normalisation et detection uniquement
  --audit-only     Audit offensif uniquement

Securite:
  - Chemins FIFO randomises avec mktemp pour protection contre les symlink
  - Fichier PID stocke dans repertoire temporaire securise (mode 0700)
  - Toutes les donnees sensibles de argv sont masquees avant traitement
  - Validation des conditions jq previent les injections

Codes de sortie:
  100  Option inconnue
  101  Parametre obligatoire manquant
  102  Fichier requis absent
  103  Privileges insuffisants
  104  Commande requise absente
  105  Erreur tracefs
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -f)
                EXEC_MODE="fork"
                shift
                ;;
            -t)
                EXEC_MODE="thread"
                # L'avertissement est emis immediatement a l'analyse des arguments l'utilisateur
                # n'a pas a attendre le debut du pipeline pour apprendre que -t est un alias
                log_warn "SYSTEM" "Le mode thread n est pas implemente en bash pur; le pipeline tournera en sequential"
                shift
                ;;
            -s)
                EXEC_MODE="subshell"
                shift
                ;;
            -l)
                [[ -n "${2:-}" ]] || {
                    log_error "SYSTEM" "Option -l requiert un repertoire en argument"
                    show_help
                    exit $ERR_MISSING_PARAM
                }
                LOG_DIR="$2"
                LOG_FILE="$LOG_DIR/history.log"
                shift 2
                ;;
            -r)
                restore_defaults
                exit 0
                ;;
            sequential|fork|subshell)
                EXEC_MODE="$1"
                shift
                ;;
            thread)
                EXEC_MODE="$1"
                # Meme avertissement que pour -t la forme positionnelle suit la meme regle
                log_warn "SYSTEM" "Le mode thread n est pas implemente en bash pur; le pipeline tournera en sequential"
                shift
                ;;
            sample|stdin|live|auto)
                INPUT_MODE="$1"
                shift
                ;;
            file)
                INPUT_MODE="file"
                INPUT_FILE="${2:-}"
                [[ -n "$INPUT_FILE" ]] || {
                    log_error "SYSTEM" "Missing file after 'file'"
                    show_help
                    exit $ERR_MISSING_PARAM
                }
                shift 2
                ;;
            --sample)
                INPUT_MODE="sample"
                shift
                ;;
            --stdin)
                INPUT_MODE="stdin"
                shift
                ;;
            --live)
                INPUT_MODE="live"
                shift
                ;;
            --input)
                INPUT_MODE="file"
                INPUT_FILE="${2:-}"
                [[ -n "$INPUT_FILE" ]] || {
                    log_error "SYSTEM" "Missing file after --input"
                    show_help
                    exit $ERR_MISSING_PARAM
                }
                shift 2
                ;;
            --pipeline-only)
                RUN_MODE="pipeline_only"
                shift
                ;;
            --audit-only)
                RUN_MODE="audit_only"
                shift
                ;;
            *)
                log_error "SYSTEM" "Option inconnue: $1"
                show_help
                exit $ERR_UNKNOWN_OPTION
                ;;
        esac
    done
}

main() {
    load_rules_conf
    # Premier essai avec le repertoire par defaut les messages de demarrage ont deja quelque chose ou ecrire.
    ensure_log_dir || true

    case "${1:-}" in
        capture-start)
            shift
            m1_capture_start "$@"
            return
            ;;
        capture-stop)
            shift
            m1_capture_stop "$@"
            return
            ;;
        capture-status)
            shift
            m1_capture_status "$@"
            return
            ;;
    esac

    parse_args "$@"
    # Si -l a change LOG_DIR on reessaie avec le nouveau chemin avant que les vrais logs commencent
    ensure_log_dir || log_warn "SYSTEM" "Log directory unavailable: $LOG_DIR"

    trap cleanup_runtime EXIT INT TERM

    check_prerequisites
    m2_prepare_detection_state
    m2_load_detection_rules

    log_section "Starting analysis stage"

    case "$RUN_MODE" in
        audit_only)
            run_offensive_audit
            ;;
        pipeline_only)
            run_pipeline
            ;;
        full)
            start_defensive_background
            run_offensive_audit
            run_pipeline
            ;;
        *)
            log_error "SYSTEM" "Unknown run mode: $RUN_MODE"
            return 1
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
