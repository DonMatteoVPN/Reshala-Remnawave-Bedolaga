#!/bin/bash
# ============================================================ #
# ==             SKYNET: УПРАВЛЕНИЕ БАЗОЙ ФЛОТА             == #
# ============================================================ #
#
# Модуль отвечает за CRUD операции с базой данных серверов
# и вспомогательные функции проверки версий.
#
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска

# --- ВЕРСИОННЫЕ ХЕЛПЕРЫ ДЛЯ SKYNET ---
# Нормализация версии: убираем префикс v/V
_skynet_normalize_version() {
    echo "$1" | sed 's/^[vV]//' 2>/dev/null
}

# Возвращает 0 (успех), если локальный ЦУП новее удалённого агента
_skynet_is_local_newer() {
    local local_v remote_v
    local_v=$(_skynet_normalize_version "$1")
    remote_v=$(_skynet_normalize_version "$2")

    # Если одинаковые — обновлять не нужно
    if [[ "$local_v" == "$remote_v" ]]; then
        return 1
    fi

    local top
    top=$(printf '%s\n%s\n' "$local_v" "$remote_v" | sort -V | tail -n1)
    if [[ "$top" == "$local_v" ]]; then
        return 0
    fi
    return 1
}

_sanitize_fleet_database() {
    if [ -f "$FLEET_DATABASE_FILE" ]; then
        local original_file="$FLEET_DATABASE_FILE"
        local temp_file=$(mktemp)
        local modified_count=0

        # Read original file line by line
        while IFS='|' read -r name user ip port key_path sudo_pass; do
            local current_line="$name|$user|$ip|$port|$key_path|$sudo_pass"
            local new_key_path="$key_path"

            # Check if it's an old-style unique key and needs migration
            # Condition: starts with SKYNET_UNIQUE_KEY_PREFIX, has an IP, and doesn't have an IP part in the filename yet
            if [[ "$key_path" == "${HOME}/.ssh/${SKYNET_UNIQUE_KEY_PREFIX}"* ]] && [[ -n "$ip" ]]; then
                # Extract the old key_name part from the path
                local old_key_filename=$(basename "$key_path")
                local safe_name_part=$(echo "$name" | tr -cd '[:alnum:]_-')
                local safe_ip_part=$(echo "$ip" | tr '.' '_')
                local expected_new_filename="${SKYNET_UNIQUE_KEY_PREFIX}${safe_name_part}_${safe_ip_part}"

                # Compare current filename with the expected new filename
                # If they are different, it's an old-style key that needs updating
                if [[ "$old_key_filename" != "$expected_new_filename" ]]; then
                    # Generate the new key path using the new convention
                    # _generate_unique_key is expected to return the new path
                    new_key_path=$(_generate_unique_key "$name" "$ip") >/dev/null # Suppress stdout
                    modified_count=$((modified_count + 1))
                    printf_info "Migrated key path for '${name}' (old: ${key_path}, new: ${new_key_path})" >&2
                    current_line="$name|$user|$ip|$port|$new_key_path|$sudo_pass"
                fi
            fi
            echo "$current_line" >> "$temp_file"
        done < "$original_file"

        # Overwrite the original file only if changes were made
        if [[ "$modified_count" -gt 0 ]]; then
            mv "$temp_file" "$original_file"
            printf_ok "Fleet database migrated: updated $modified_count unique key paths." >&2
        else
            rm "$temp_file"
        fi

        # Original cleanup logic (remove empty lines and invalid entries)
        sed -i '/^$/d' "$FLEET_DATABASE_FILE"

        local tmp_filter=$(mktemp)
        while IFS='|' read -r name user ip port key_path sudo_pass; do
            if [[ -z "$name" ]] || [[ "$name" == $'\e'* ]]; then
                continue
            fi
            if [[ -z "$ip" ]]; then
                continue
            fi
            echo "$name|$user|$ip|$port|$key_path|$sudo_pass" >> "$tmp_filter"
        done < "$FLEET_DATABASE_FILE"
        mv "$tmp_filter" "$FLEET_DATABASE_FILE"
    fi
}

_update_fleet_record() {
    local line_num="$1"; local new_record="$2"
    local temp_file; temp_file=$(mktemp)
    awk -v line="$line_num" -v new_rec="$new_record" 'NR==line {print new_rec} NR!=line {print}' "$FLEET_DATABASE_FILE" > "$temp_file"
    mv "$temp_file" "$FLEET_DATABASE_FILE"
}

# Removes references to a specific key_path from the FLEET_DATABASE_FILE
_remove_key_path_from_fleet_db() {
    local deleted_key_path="$1"
    local original_file="$FLEET_DATABASE_FILE"
    local temp_file=$(mktemp)
    local modified_count=0

    if [ ! -f "$original_file" ]; then
        return # No database to update
    fi

    while IFS='|' read -r name user ip port key_path sudo_pass; do
        if [[ "$key_path" == "$deleted_key_path" ]]; then
            # Found a matching entry, remove the key_path
            echo "$name|$user|$ip|$port||$sudo_pass" >> "$temp_file"
            modified_count=$((modified_count + 1))
        else
            echo "$name|$user|$ip|$port|$key_path|$sudo_pass" >> "$temp_file"
        fi
    done < "$original_file"

    if [[ "$modified_count" -gt 0 ]]; then
        mv "$temp_file" "$original_file"
        printf_info "Обновлена база флота: удалено %d ссылок на удаленный ключ." "$modified_count" >&2
    else
        rm "$temp_file"
    fi
}