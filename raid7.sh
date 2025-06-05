#!/bin/bash

#set -xuevo pipefail
set -e

# Список серверов для аудита (скопирован из audit2.sh)
SERVERS=(
    "192.168.72.4:service"
    "192.168.72.5:service"
    "192.168.72.6:service"
    "192.168.72.7:service"
)

# SSH пользователь
SSH_USER="saltuser"

# Директория с результатами аудита
AUDIT_DIR=${1:-"server_audit_$(date +%Y%m%d)"}

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функция для извлечения IP адресов серверов
get_server_ips() {
    local server_ips=()
    for server_info in "${SERVERS[@]}"; do
        local server_ip=$(echo "$server_info" | cut -d: -f1)
        server_ips+=("$server_ip")
    done
    echo "${server_ips[@]}"
}

# Функция для создания заголовка таблицы
create_header() {
    local server_ips=($(get_server_ips))
    local header="Раздел элемента аудита;Имя файла вывода;Команда;Род вывода;Вид части вывода"

    for server_ip in "${server_ips[@]}"; do
        header="$header;$server_ip"
    done

    echo "$header"
}

# Функция для выполнения команды на удаленном сервере
execute_remote_command() {
    local server_info="$1"
    local command="$2"
    local server_ip=$(echo "$server_info" | cut -d: -f1)
    local user=$(echo "$server_info" | cut -d: -f2)
    
    ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$SSH_USER@$server_ip" "$command" 2>/dev/null || true
}

# Функция для проверки наличия RAID контроллеров
check_raid_controllers() {
    local server_info="$1"
    local server_ip=$(echo "$server_info" | cut -d: -f1)
    
    printf "[INFO] Проверка RAID контроллеров на %s...\n" "$server_ip" >&2
    
    # Проверяем наличие LSI/Broadcom контроллеров через lspci
    local lspci_output
    lspci_output=$(execute_remote_command "$server_info" "lspci | grep -i 'lsi\|broadcom\|megaraid\|sas'") || true
    
    if [[ -n "$lspci_output" ]]; then
        printf "[FOUND] RAID контроллеры найдены на %s:\n" "$server_ip" >&2
        printf "%s\n" "$lspci_output" >&2
        return 0
    else
        printf "[NOT FOUND] RAID контроллеры не найдены на %s\n" "$server_ip" >&2
        return 1
    fi
}

# Функция для проверки наличия утилит управления RAID
check_raid_utilities() {
    local server_info="$1"
    local server_ip=$(echo "$server_info" | cut -d: -f1)
    
    printf "[INFO] Проверка утилит управления RAID на %s...\n" "$server_ip" >&2
    
    # Проверяем StorCLI
    local storcli_path=""
    local paths=("/opt/MegaRAID/storcli/storcli64" "/usr/local/bin/storcli64" "/usr/bin/storcli64")
    for path in "${paths[@]}"; do
        if execute_remote_command "$server_info" "test -f $path"; then
            storcli_path="$path"
            break
        fi
    done
    
    # Проверяем MegaCLI
    local megacli_path=""
    local megacli_paths=("/opt/MegaRAID/MegaCli/MegaCli64" "/usr/local/bin/MegaCli64" "/usr/bin/MegaCli64" "/usr/sbin/MegaCli64")
    for path in "${megacli_paths[@]}"; do
        if execute_remote_command "$server_info" "test -f $path"; then
            megacli_path="$path"
            break
        fi
    done
    
    # Возвращаем результат
    printf "%s|%s\n" "$storcli_path" "$megacli_path"
}

# Функция для установки StorCLI
install_storcli() {
    local server_info="$1"
    local server_ip=$(echo "$server_info" | cut -d: -f1)
    
    printf "[INFO] Установка StorCLI на %s...\n" "$server_ip" >&2
    
    local install_script='
        set -e
        cd /tmp
        # Скачиваем StorCLI (примерная ссылка, нужно заменить на актуальную)
        if wget -q https://docs.broadcom.com/docs-and-downloads/raid-controllers/raid-controllers-common-files/storcli_rel.zip; then
            unzip -q storcli_rel.zip
            cd storcli_rel*/Linux/
            if rpm -ivh storcli-*.rpm 2>/dev/null; then
                echo "StorCLI установлен успешно"
            else
                echo "Ошибка установки StorCLI"
            fi
            cd /tmp && rm -rf storcli_rel*
        else
            echo "Ошибка загрузки StorCLI"
        fi
    '
    
    execute_remote_command "$server_info" "$install_script"
}

# Функция для установки MegaCLI
install_megacli() {
    local server_info="$1"
    local server_ip=$(echo "$server_info" | cut -d: -f1)
    
    printf "[INFO] Установка MegaCLI на %s...\n" "$server_ip" >&2
    
    local install_script='
        set -e
        cd /tmp
        # Скачиваем MegaCLI (примерная ссылка, нужно заменить на актуальную)
        if wget -q http://www.lsi.com/downloads/Public/MegaRAID%20Common%20Files/8.07.14_MegaCLI.zip; then
            unzip -q 8.07.14_MegaCLI.zip
            cd Linux/
            if rpm -ivh MegaCli-*.rpm 2>/dev/null; then
                echo "MegaCLI установлен успешно"
            else
                echo "Ошибка установки MegaCLI"
            fi
            cd /tmp && rm -rf Linux/ 8.07.14_MegaCLI.zip
        else
            echo "Ошибка загрузки MegaCLI"
        fi
    '
    
    execute_remote_command "$server_info" "$install_script"
}

# Функция для сбора информации о RAID
collect_raid_info() {
    local server_info="$1"
    local storcli_path="$2"
    local megacli_path="$3"
    local server_ip=$(echo "$server_info" | cut -d: -f1)
    local output_file="$AUDIT_DIR/$server_ip/02_raid_info.txt"
    
    # Создаем директорию если не существует
    mkdir -p "$AUDIT_DIR/$server_ip"
    
    echo "=== RAID Controller Information for $server_ip ===" > "$output_file"
    echo "Timestamp: $(date)" >> "$output_file"
    echo "" >> "$output_file"
    
    # Информация о контроллерах через lspci
    echo "=== PCI RAID Controllers ===" >> "$output_file"
    execute_remote_command "$server_info" "lspci | grep -i 'lsi\|broadcom\|megaraid\|sas'" >> "$output_file" || true
    echo "" >> "$output_file"
    
    # Если есть StorCLI
    if [[ -n "$storcli_path" ]]; then
        echo "== StorCLI Information ==" >> "$output_file"
        echo "StorCLI Path: $storcli_path" >> "$output_file"
        echo "" >> "$output_file"
        
        # Версия StorCLI
        echo "--- StorCLI Version --- # Вывод команды sudo $storcli_path show" >> "$output_file"
        execute_remote_command "$server_info" "sudo $storcli_path show" >> "$output_file" || true
        echo "" >> "$output_file"
        
        # Детальная информация о контроллере 0 (если есть)
        echo "--- Controller 0 Details --- # Вывод команды sudo $storcli_path /c0 show" >> "$output_file"
        execute_remote_command "$server_info" "sudo $storcli_path /c0 show" >> "$output_file" || true
        echo "" >> "$output_file"
        
    # Если есть MegaCLI
    elif [[ -n "$megacli_path" ]]; then
        echo "=== MegaCLI Information ===" >> "$output_file"
        echo "MegaCLI Path: $megacli_path" >> "$output_file"
        echo "" >> "$output_file"
        
        # Информация о контроллерах
        echo "--- Controllers Information ---" >> "$output_file"
        execute_remote_command "$server_info" "sudo $megacli_path -AdpAllInfo -aALL" >> "$output_file" || true
        echo "" >> "$output_file"
        
        # Физические диски
        echo "--- Physical Drives ---" >> "$output_file"
        execute_remote_command "$server_info" "sudo $megacli_path -PDList -aALL" >> "$output_file" || true
        echo "" >> "$output_file"
        
        # Логические диски
        echo "--- Logical Drives ---" >> "$output_file"
        execute_remote_command "$server_info" "sudo $megacli_path -LDInfo -Lall -aALL" >> "$output_file" || true
        echo "" >> "$output_file"
        
    else
        echo "No RAID management utilities found" >> "$output_file"
    fi
    
    echo -e "${GREEN}[DONE]${NC} Информация о RAID сохранена в $output_file"
}

# Функция для парсинга StorCLI данных
parse_storcli_data() {
    local server_ip="$1"
    local input_file="$AUDIT_DIR/$server_ip/02_raid_info.txt"
    local parameter="$2"
    
    if [[ ! -f "$input_file" ]]; then
        echo "N/A"
        return
    fi
    
    case "$parameter" in
        "controller_count")
            # Подсчитываем количество контроллеров из строки "Number of Controllers = X"
            grep "Number of Controllers" "$input_file" 2>/dev/null | sed -n 's/.*= *\([0-9]\+\).*/\1/p' | head -1 || echo "0"
            ;;
        "controller_model")
            # Модель контроллера
            grep "Product Name" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "controller_serial")
            # Серийный номер контроллера
            grep "Serial Number" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "sas_address")
            # SAS Address
            grep "SAS Address" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "pci_address")
            # PCI Address
            grep "PCI Address" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "firmware_version")
            # Версия прошивки
            grep "FW Version" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "fw_package_build")
            # FW Package Build
            grep "FW Package Build" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "bios_version")
            # Версия BIOS
            grep "BIOS Version" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "driver_name")
            # Имя драйвера
            grep "Driver Name" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "driver_version")
            # Версия драйвера
            grep "Driver Version" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "personality")
            # Current Personality
            grep "Current Personality" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "host_interface")
            # Host Interface
            grep "Host Interface" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "drive_groups")
            # Количество групп дисков
            grep "Drive Groups" "$input_file" 2>/dev/null | sed -n 's/.*= *\([0-9]\+\).*/\1/p' | head -1 || echo "0"
            ;;
        "virtual_drives")
            # Количество виртуальных дисков
            grep "Virtual Drives" "$input_file" 2>/dev/null | sed -n 's/.*= *\([0-9]\+\).*/\1/p' | head -1 || echo "0"
            ;;
        "physical_drives")
            # Количество физических дисков
            grep "Physical Drives" "$input_file" 2>/dev/null | sed -n 's/.*= *\([0-9]\+\).*/\1/p' | head -1 || echo "0"
            ;;
        "enclosures")
            # Количество корпусов
            grep "Enclosures" "$input_file" 2>/dev/null | sed -n 's/.*= *\([0-9]\+\).*/\1/p' | head -1 || echo "0"
            ;;
        "system_time")
            # Системное время
            grep "System Time" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "controller_time")
            # Время контроллера
            grep "Controller Time" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "mfg_date")
            # Дата производства
            grep "Mfg. Date" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "security_protocol")
            # Протокол безопасности
            grep "Security Protocol" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "cachevault_model")
            # Модель CacheVault
            grep -A3 "Cachevault_Info" "$input_file" 2>/dev/null | grep -v "^-\|^Model\|^=\|^$" | head -1 | awk '{print $1}' || echo "N/A"
            ;;
        "cachevault_state")
            # Состояние CacheVault
            grep -A3 "Cachevault_Info" "$input_file" 2>/dev/null | grep -v "^-\|^Model\|^=\|^$" | head -1 | awk '{print $2}' || echo "N/A"
            ;;
        "cachevault_temp")
            # Температура CacheVault
            grep -A3 "Cachevault_Info" "$input_file" 2>/dev/null | grep -v "^-\|^Model\|^=\|^$" | head -1 | awk '{print $3}' || echo "N/A"
            ;;
        "cachevault_mode")
            # Режим CacheVault
            grep -A3 "Cachevault_Info" "$input_file" 2>/dev/null | grep -v "^-\|^Model\|^=\|^$" | head -1 | awk '{print $4}' || echo "N/A"
            ;;
        "cachevault_mfg_date")
            # Дата производства CacheVault
            grep -A3 "Cachevault_Info" "$input_file" 2>/dev/null | grep -v "^-\|^Model\|^=\|^$" | head -1 | awk '{print $5}' || echo "N/A"
            ;;
        "raid_levels")
            # RAID уровни из VD LIST
            sed -n '/^VD LIST/,/^$/p' "$input_file" 2>/dev/null | grep -E '^[0-9]+/[0-9]+' | awk '{print $2}' | sort -u | tr '\n' ',' | sed 's/,$//' || echo "N/A"
            ;;
        "vd_info")
            # Информация о виртуальных дисках (формат: DG/VD:TYPE:Size)
            sed -n '/^VD LIST/,/^$/p' "$input_file" 2>/dev/null | grep -E '^[0-9]+/[0-9]+' | awk '{print $1":"$2":"$(NF-1)" "$(NF)}' | tr '\n' '; ' | sed 's/; $//' || echo "N/A"
            ;;
        "pd_count_by_type")
            # Количество физических дисков по типу (SSD/HDD)
            local ssd_count=$(sed -n '/^PD LIST/,/^$/p' "$input_file" 2>/dev/null | grep -E '^[0-9]+:[0-9]+' | grep SSD | wc -l)
            local hdd_count=$(sed -n '/^PD LIST/,/^$/p' "$input_file" 2>/dev/null | grep -E '^[0-9]+:[0-9]+' | grep HDD | wc -l)
            echo "SSD:$ssd_count;HDD:$hdd_count"
            ;;
        "system_overview")
            # Системный обзор из таблицы System Overview
            sed -n '/^System Overview/,/^$/p' "$input_file" 2>/dev/null | grep -E '^[ ]*[0-9]' | head -1 | awk '{print "Ctl:"$2";Ports:"$3";PDs:"$4";DGs:"$5";VDs:"$7";BBU:"$9";Health:"$NF}' || echo "N/A"
            ;;
        "topology_summary")
            # Краткая сводка топологии
            local raid1_count=$(sed -n '/^TOPOLOGY/,/^$/p' "$input_file" 2>/dev/null | grep -c "RAID1" || echo "0")
            local raid10_count=$(sed -n '/^TOPOLOGY/,/^$/p' "$input_file" 2>/dev/null | grep -c "RAID10" || echo "0")
            echo "RAID1:$raid1_count;RAID10:$raid10_count"
            ;;
        "degraded_drives")
            # Деградированные диски (поиск статусов отличных от Optl/Onln)
            sed -n '/^TOPOLOGY/,/^$/p' "$input_file" 2>/dev/null | grep -v "Optl\|Onln" | grep -E "Dgrd|Offln|Failed" | wc -l || echo "0"
            ;;
        "enclosure_info")
            # Информация о корпусах
            sed -n '/^Enclosure LIST/,/^$/p' "$input_file" 2>/dev/null | grep -E '^[ ]*[0-9]+' | awk '{print $1":"$2":"$3"PD"}' | tr '\n' '; ' | sed 's/; $//' || echo "N/A"
            ;;
        *)
            echo "N/A"
            ;;
    esac
}

# Функция для парсинга MegaCLI данных
parse_megacli_data() {
    local server_ip="$1"
    local input_file="$AUDIT_DIR/$server_ip/02_raid_info.txt"
    local parameter="$2"
    
    if [[ ! -f "$input_file" ]]; then
        echo "N/A"
        return
    fi
    
    case "$parameter" in
        "controller_count")
            grep -c "Adapter #" "$input_file" 2>/dev/null || echo "0"
            ;;
        "controller_model")
            grep "Product Name" "$input_file" | head -1 | cut -d: -f2 | xargs || echo "N/A"
            ;;
        "controller_serial")
            grep "Serial No" "$input_file" | head -1 | cut -d: -f2 | xargs || echo "N/A"
            ;;
        "firmware_version")
            grep "FW Version" "$input_file" | head -1 | cut -d: -f2 | xargs || echo "N/A"
            ;;
        "bios_version")
            grep "BIOS Version" "$input_file" | head -1 | cut -d: -f2 | xargs || echo "N/A"
            ;;
        "memory_size")
            grep "Memory Size" "$input_file" | head -1 | cut -d: -f2 | xargs || echo "N/A"
            ;;
        "physical_drives")
            grep -c "Device Id:" "$input_file" 2>/dev/null || echo "0"
            ;;
        "virtual_drives")
            grep -c "Virtual Drive:" "$input_file" 2>/dev/null || echo "0"
            ;;
        "controller_status")
            grep "Controller Status" "$input_file" | head -1 | cut -d: -f2 | xargs || echo "N/A"
            ;;
        "bbu_status")
            grep -i "battery\|bbu" "$input_file" | grep -i "state" | head -1 | cut -d: -f2 | xargs || echo "N/A"
            ;;
        "drive_groups")
            grep "Drive Groups:" "$input_file" | wc -l 2>/dev/null || echo "0"
            ;;
        "raid_levels")
            grep "RAID Level" "$input_file" | cut -d: -f2 | sort -u | tr '\n' ',' | sed 's/,$//' || echo "N/A"
            ;;
        "total_capacity")
            grep -i "size\|capacity" "$input_file" | grep -E '[0-9]+\s*(GB|TB|MB)' | head -1 | grep -oE '[0-9.]+\s*(GB|TB|MB)' || echo "N/A"
            ;;
        "degraded_drives")
            grep -i "failed\|degraded\|offline" "$input_file" | wc -l 2>/dev/null || echo "0"
            ;;
        "rebuild_progress")
            grep -i "rebuild" "$input_file" | grep -oE '[0-9]+%' | head -1 || echo "N/A"
            ;;
        *)
            echo "N/A"
            ;;
    esac
}

# Универсальная функция парсинга данных RAID
parse_raid_parameter() {
    local server_ip="$1"
    local parameter="$2"
    local input_file="$AUDIT_DIR/$server_ip/02_raid_info.txt"
    
    if [[ ! -f "$input_file" ]]; then
        echo "N/A"
        return
    fi
    
    # Определяем тип утилиты по содержимому файла
    if grep -q "StorCLI Information" "$input_file"; then
        parse_storcli_data "$server_ip" "$parameter"
    elif grep -q "MegaCLI Information" "$input_file"; then
        parse_megacli_data "$server_ip" "$parameter"
    else
        case "$parameter" in
            "controller_count"|"physical_drives"|"virtual_drives"|"drive_groups"|"degraded_drives"|"enclosures")
                echo "0"
                ;;
            *)
                echo "N/A"
                ;;
        esac
    fi
}

# Функция для создания строки таблицы с детализированным парсингом
create_detailed_raid_table_row() {
    local audit_section="$1"
    local filename="$2"
    local command="$3"
    local output_category="$4"
    local parameter_type="$5"
    local parameter_name="$6"
    local server_ips=($(get_server_ips))
    
    local row="$audit_section;$filename;$command;$output_category;$parameter_type"
    
    # Собираем данные со всех серверов
    for server_ip in "${server_ips[@]}"; do
        local value=$(parse_raid_parameter "$server_ip" "$parameter_name")
        row="$row;$value"
    done
    
    echo "$row"
}

# Функция для создания детализированной таблицы с информацией о RAID
create_detailed_raid_info_table() {
    # Выводим заголовок
    create_header
    
    # lspci команда для обнаружения контроллеров
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "lspci | grep -i 'lsi|broadcom|megaraid|sas'" "Аппаратная конфигурация" "Обнаружение RAID контроллеров" "controller_count"
    
    # StorCLI show - общая информация
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 show" "Информация о контроллере" "Количество контроллеров" "controller_count"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 show" "Информация о контроллере" "Системный обзор" "system_overview"
    
    # StorCLI /c0 show - детальная информация о контроллере
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Модель контроллера" "controller_model"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Серийный номер" "controller_serial"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "SAS Address" "sas_address"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "PCI Address" "pci_address"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Версия прошивки" "firmware_version"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "FW Package Build" "fw_package_build"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Версия BIOS" "bios_version"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Имя драйвера" "driver_name"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Версия драйвера" "driver_version"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Текущий режим" "personality"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Интерфейс хоста" "host_interface"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Системное время" "system_time"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Время контроллера" "controller_time"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Дата производства" "mfg_date"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Протокол безопасности" "security_protocol"
    
    # Статистика дисков и групп
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Статистика дисков" "Группы дисков" "drive_groups"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Статистика дисков" "Виртуальные диски" "virtual_drives"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Статистика дисков" "Физические диски" "physical_drives"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Статистика дисков" "Корпуса" "enclosures"
    
    # Информация о CacheVault/BBU
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Информация о BBU" "Модель CacheVault" "cachevault_model"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Информация о BBU" "Состояние CacheVault" "cachevault_state"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Информация о BBU" "Температура CacheVault" "cachevault_temp"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Информация о BBU" "Режим CacheVault" "cachevault_mode"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Информация о BBU" "Дата производства CacheVault" "cachevault_mfg_date"
    
    # RAID конфигурация
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Конфигурация RAID" "RAID уровни" "raid_levels"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Конфигурация RAID" "Информация о VD" "vd_info"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Конфигурация RAID" "Диски по типу" "pd_count_by_type"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Конфигурация RAID" "Краткая сводка топологии" "topology_summary"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Конфигурация RAID" "Деградированные диски" "degraded_drives"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Конфигурация RAID" "Информация о корпусах" "enclosure_info"
}

# Функция для парсинга StorCLI данных (исправленная версия)
parse_storcli_data() {
    local server_ip="$1"
    local input_file="$AUDIT_DIR/$server_ip/02_raid_info.txt"
    local parameter="$2"
    
    if [[ ! -f "$input_file" ]]; then
        echo "N/A"
        return
    fi
    
    case "$parameter" in
        "controller_count")
            # Подсчитываем количество контроллеров из строки "Number of Controllers = X"
            grep "Number of Controllers" "$input_file" 2>/dev/null | sed -n 's/.*= *\([0-9]\+\).*/\1/p' | head -1 || echo "0"
            ;;
        "controller_model")
            # Модель контроллера из строки "Product Name = "
            grep "^Product Name" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "controller_serial")
            # Серийный номер контроллера из строки "Serial Number = "
            grep "^Serial Number" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "sas_address")
            # SAS Address из строки "SAS Address = "
            grep "^SAS Address" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "pci_address")
            # PCI Address из строки "PCI Address = "
            grep "^PCI Address" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "firmware_version")
            # Версия прошивки из строки "FW Version = "
            grep "^FW Version" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "fw_package_build")
            # FW Package Build из строки "FW Package Build = "
            grep "^FW Package Build" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "bios_version")
            # Версия BIOS из строки "BIOS Version = "
            grep "^BIOS Version" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "driver_name")
            # Имя драйвера из строки "Driver Name = "
            grep "^Driver Name" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "driver_version")
            # Версия драйвера из строки "Driver Version = "
            grep "^Driver Version" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "personality")
            # Current Personality из строки "Current Personality = "
            grep "^Current Personality" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "host_interface")
            # Host Interface из строки "Host Interface = "
            grep "^Host Interface" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "drive_groups")
            # Количество групп дисков из строки "Drive Groups = "
            grep "^Drive Groups" "$input_file" 2>/dev/null | sed -n 's/.*= *\([0-9]\+\).*/\1/p' | head -1 || echo "0"
            ;;
        "virtual_drives")
            # Количество виртуальных дисков из строки "Virtual Drives = "
            grep "^Virtual Drives" "$input_file" 2>/dev/null | sed -n 's/.*= *\([0-9]\+\).*/\1/p' | head -1 || echo "0"
            ;;
        "physical_drives")
            # Количество физических дисков из строки "Physical Drives = "
            grep "^Physical Drives" "$input_file" 2>/dev/null | sed -n 's/.*= *\([0-9]\+\).*/\1/p' | head -1 || echo "0"
            ;;
        "enclosures")
            # Количество корпусов из строки "Enclosures = "
            grep "^Enclosures" "$input_file" 2>/dev/null | sed -n 's/.*= *\([0-9]\+\).*/\1/p' | head -1 || echo "0"
            ;;
        "system_time")
            # Системное время из строки "System Time = "
            grep "^System Time" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "controller_time")
            # Время контроллера из строки "Controller Time = "
            grep "^Controller Time" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "mfg_date")
            # Дата производства из строки "Mfg. Date = "
            grep "^Mfg. Date" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "security_protocol")
            # Протокол безопасности из строки "Security Protocol = "
            grep "^Security Protocol" "$input_file" 2>/dev/null | sed -n 's/.*= *\(.*\)/\1/p' | head -1 | xargs || echo "N/A"
            ;;
        "cachevault_model")
            # Модель CacheVault из таблицы Cachevault_Info
            awk '/^Cachevault_Info/,/^$/{if(NF>=4 && $1!~/^-+$/ && $1!~/Model/ && $1!~/^=/) print $1}' "$input_file" 2>/dev/null | head -1 || echo "N/A"
            ;;
        "cachevault_state")
            # Состояние CacheVault из таблицы Cachevault_Info
            awk '/^Cachevault_Info/,/^$/{if(NF>=4 && $1!~/^-+$/ && $1!~/Model/ && $1!~/^=/) print $2}' "$input_file" 2>/dev/null | head -1 || echo "N/A"
            ;;
        "cachevault_temp")
            # Температура CacheVault из таблицы Cachevault_Info
            awk '/^Cachevault_Info/,/^$/{if(NF>=4 && $1!~/^-+$/ && $1!~/Model/ && $1!~/^=/) print $3}' "$input_file" 2>/dev/null | head -1 || echo "N/A"
            ;;
        "cachevault_mode")
            # Режим CacheVault из таблицы Cachevault_Info
            awk '/^Cachevault_Info/,/^$/{if(NF>=4 && $1!~/^-+$/ && $1!~/Model/ && $1!~/^=/) print $4}' "$input_file" 2>/dev/null | head -1 || echo "N/A"
            ;;
        "cachevault_mfg_date")
            # Дата производства CacheVault из таблицы Cachevault_Info
            awk '/^Cachevault_Info/,/^$/{if(NF>=5 && $1!~/^-+$/ && $1!~/Model/ && $1!~/^=/) print $5}' "$input_file" 2>/dev/null | head -1 || echo "N/A"
            ;;
        "raid_levels")
            # RAID уровни из таблицы VD LIST
            awk '/^VD LIST/,/^$/{if($0~/^[0-9]+\/[0-9]+/ && NF>=8) print $3}' "$input_file" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//' || echo "N/A"
            ;;
        "vd_info")
            # Информация о виртуальных дисках (формат: DG/VD:TYPE:Size:Name)
            awk '/^VD LIST/,/^$/{if($0~/^[0-9]+\/[0-9]+/ && NF>=9) print $1":"$3":"$(NF-1)" "$(NF-2)":"$NF}' "$input_file" 2>/dev/null | tr '\n' '; ' | sed 's/; $//' || echo "N/A"
            ;;
        "pd_count_by_type")
            # Количество физических дисков по типу (SSD/HDD) из таблицы PD LIST
            local ssd_count=$(awk '/^PD LIST/,/^$/{if($0~/^[0-9]+:[0-9]+/ && NF>=10 && $8=="SSD") count++} END{print count+0}' "$input_file" 2>/dev/null)
            local hdd_count=$(awk '/^PD LIST/,/^$/{if($0~/^[0-9]+:[0-9]+/ && NF>=10 && $8=="HDD") count++} END{print count+0}' "$input_file" 2>/dev/null)
            echo "SSD:$ssd_count;HDD:$hdd_count"
            ;;
        "system_overview")
            # Системный обзор из таблицы System Overview
            awk '/^System Overview/,/^$/{if($0~/^[ ]*[0-9]/ && NF>=10) print "Ctl:"$2";Ports:"$3";PDs:"$4";DGs:"$5";VDs:"$7";BBU:"$9";Health:"$NF}' "$input_file" 2>/dev/null | head -1 || echo "N/A"
            ;;
        "topology_summary")
            # Краткая сводка топологии из таблицы TOPOLOGY
            local raid1_count=$(awk '/^TOPOLOGY/,/^$/{if($0~/RAID1/) count++} END{print count+0}' "$input_file" 2>/dev/null)
            local raid10_count=$(awk '/^TOPOLOGY/,/^$/{if($0~/RAID10/) count++} END{print count+0}' "$input_file" 2>/dev/null)
            echo "RAID1:$raid1_count;RAID10:$raid10_count"
            ;;
        "degraded_drives")
            # Деградированные диски (поиск статусов отличных от Optl/Optn/Onln)
            awk '/^TOPOLOGY/,/^$/{if($0~/^[ ]*[0-9]/ && $6!~/Optl|Optn|Onln/ && $6~/Dgrd|Offln|Failed/) count++} END{print count+0}' "$input_file" 2>/dev/null || echo "0"
            ;;
        "enclosure_info")
            # Информация о корпусах из таблицы Enclosure LIST
            awk '/^Enclosure LIST/,/^$/{if($0~/^[ ]*[0-9]+/ && NF>=10) print $1":"$2":"$3"PD"}' "$input_file" 2>/dev/null | tr '\n' '; ' | sed 's/; $//' || echo "N/A"
            ;;
        *)
            echo "N/A"
            ;;
    esac
}

# Функция для парсинга MegaCLI данных (обновленная версия)
parse_megacli_data() {
    local server_ip="$1"
    local input_file="$AUDIT_DIR/$server_ip/02_raid_info.txt"
    local parameter="$2"
    
    if [[ ! -f "$input_file" ]]; then
        echo "N/A"
        return
    fi
    
    case "$parameter" in
        "controller_count")
            grep -c "Adapter #" "$input_file" 2>/dev/null || echo "0"
            ;;
        "controller_model")
            grep "Product Name" "$input_file" 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "N/A"
            ;;
        "controller_serial")
            grep "Serial No" "$input_file" 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "N/A"
            ;;
        "firmware_version")
            grep "FW Version" "$input_file" 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "N/A"
            ;;
        "bios_version")
            grep "BIOS Version" "$input_file" 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "N/A"
            ;;
        "memory_size")
            grep "Memory Size" "$input_file" 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "N/A"
            ;;
        "physical_drives")
            grep -c "Device Id:" "$input_file" 2>/dev/null || echo "0"
            ;;
        "virtual_drives")
            grep -c "Virtual Drive:" "$input_file" 2>/dev/null || echo "0"
            ;;
        "controller_status")
            grep "Controller Status" "$input_file" 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "N/A"
            ;;
        "bbu_status")
            grep -i "battery\|bbu" "$input_file" 2>/dev/null | grep -i "state" | head -1 | cut -d: -f2 | xargs || echo "N/A"
            ;;
        "drive_groups")
            grep "Drive Groups:" "$input_file" 2>/dev/null | wc -l || echo "0"
            ;;
        "raid_levels")
            grep "RAID Level" "$input_file" 2>/dev/null | cut -d: -f2 | sort -u | tr '\n' ',' | sed 's/,$//' || echo "N/A"
            ;;
        "total_capacity")
            grep -i "size\|capacity" "$input_file" 2>/dev/null | grep -E '[0-9]+\s*(GB|TB|MB)' | head -1 | grep -oE '[0-9.]+\s*(GB|TB|MB)' || echo "N/A"
            ;;
        "degraded_drives")
            grep -i "failed\|degraded\|offline" "$input_file" 2>/dev/null | wc -l || echo "0"
            ;;
        "rebuild_progress")
            grep -i "rebuild" "$input_file" 2>/dev/null | grep -oE '[0-9]+%' | head -1 || echo "N/A"
            ;;
        # Для параметров, которые не поддерживаются в MegaCLI, возвращаем значения по умолчанию
        "sas_address"|"pci_address"|"fw_package_build"|"driver_name"|"driver_version"|"personality"|"host_interface"|"system_time"|"controller_time"|"mfg_date"|"security_protocol"|"cachevault_model"|"cachevault_state"|"cachevault_temp"|"cachevault_mode"|"cachevault_mfg_date"|"vd_info"|"pd_count_by_type"|"system_overview"|"topology_summary"|"enclosure_info")
            echo "N/A"
            ;;
        "enclosures")
            echo "0"
            ;;
        *)
            echo "N/A"
            ;;
    esac
}

# Универсальная функция парсинга данных RAID (обновленная версия)
parse_raid_parameter() {
    local server_ip="$1"
    local parameter="$2"
    local input_file="$AUDIT_DIR/$server_ip/02_raid_info.txt"
    
    if [[ ! -f "$input_file" ]]; then
        echo "N/A"
        return
    fi
    
    # Определяем тип утилиты по содержимому файла
    if grep -q "StorCLI Information" "$input_file"; then
        parse_storcli_data "$server_ip" "$parameter"
    elif grep -q "MegaCLI Information" "$input_file"; then
        parse_megacli_data "$server_ip" "$parameter"
    else
        # Если нет информации о RAID утилитах, проверяем наличие контроллеров в lspci
        if grep -q "RAID bus controller\|MegaRAID\|LSI\|Broadcom" "$input_file"; then
            # Есть контроллеры, но нет утилит
            case "$parameter" in
                "controller_count")
                    grep -c "RAID bus controller\|MegaRAID" "$input_file" 2>/dev/null || echo "0"
                    ;;
                "controller_model")
                    grep "RAID bus controller\|MegaRAID" "$input_file" 2>/dev/null | head -1 | sed 's/^[^:]*: *//' || echo "N/A"
                    ;;
                "physical_drives"|"virtual_drives"|"drive_groups"|"degraded_drives"|"enclosures")
                    echo "0"
                    ;;
                *)
                    echo "N/A"
                    ;;
            esac
        else
            # Нет контроллеров
            case "$parameter" in
                "controller_count"|"physical_drives"|"virtual_drives"|"drive_groups"|"degraded_drives"|"enclosures")
                    echo "0"
                    ;;
                *)
                    echo "N/A"
                    ;;
            esac
        fi
    fi
}

# Функция для создания строки таблицы с детализированным парсингом (без изменений)
create_detailed_raid_table_row() {
    local audit_section="$1"
    local filename="$2"
    local command="$3"
    local output_category="$4"
    local parameter_type="$5"
    local parameter_name="$6"
    local server_ips=($(get_server_ips))
    
    local row="$audit_section;$filename;$command;$output_category;$parameter_type"
    
    # Собираем данные со всех серверов
    for server_ip in "${server_ips[@]}"; do
        local value=$(parse_raid_parameter "$server_ip" "$parameter_name")
        row="$row;$value"
    done
    
    echo "$row"
}

# Функция для создания детализированной таблицы с информацией о RAID (исправленная версия)
create_detailed_raid_info_table() {
    # Выводим заголовок
    create_header
    
    # lspci команда для обнаружения контроллеров
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "lspci | grep -i 'lsi|broadcom|megaraid|sas'" "Аппаратная конфигурация" "Обнаружение RAID контроллеров" "controller_count"
    
    # StorCLI show - общая информация
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 show" "Информация о контроллере" "Количество контроллеров" "controller_count"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 show" "Информация о контроллере" "Системный обзор" "system_overview"
    
    # StorCLI /c0 show - детальная информация о контроллере
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Модель контроллера" "controller_model"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Серийный номер" "controller_serial"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "SAS Address" "sas_address"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "PCI Address" "pci_address"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Версия прошивки" "firmware_version"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "FW Package Build" "fw_package_build"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Версия BIOS" "bios_version"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Имя драйвера" "driver_name"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Версия драйвера" "driver_version"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Текущий режим" "personality"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Интерфейс хоста" "host_interface"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Системное время" "system_time"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Время контроллера" "controller_time"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Дата производства" "mfg_date"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Детальная информация контроллера" "Протокол безопасности" "security_protocol"
    
    # Статистика дисков и групп
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Статистика дисков" "Группы дисков" "drive_groups"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Статистика дисков" "Виртуальные диски" "virtual_drives"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Статистика дисков" "Физические диски" "physical_drives"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Статистика дисков" "Корпуса" "enclosures"
    
    # Информация о CacheVault/BBU
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Информация о BBU" "Модель CacheVault" "cachevault_model"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Информация о BBU" "Состояние CacheVault" "cachevault_state"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Информация о BBU" "Температура CacheVault" "cachevault_temp"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Информация о BBU" "Режим CacheVault" "cachevault_mode"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Информация о BBU" "Дата производства CacheVault" "cachevault_mfg_date"
    
    # RAID конфигурация
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Конфигурация RAID" "RAID уровни" "raid_levels"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Конфигурация RAID" "Информация о VD" "vd_info"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Конфигурация RAID" "Диски по типу" "pd_count_by_type"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Конфигурация RAID" "Краткая сводка топологии" "topology_summary"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Конфигурация RAID" "Деградированные диски" "degraded_drives"
    create_detailed_raid_table_row "RAID контроллеры" "02_raid_info.txt" "storcli64 /c0 show" "Конфигурация RAID" "Информация о корпусах" "enclosure_info"
}

# Исправленная функция парсинга StorCLI данных с учетом реального формата файла
parse_storcli_data() {
    local server_ip="$1"
    local input_file="$AUDIT_DIR/$server_ip/02_raid_info.txt"
    local parameter="$2"
    
    if [[ ! -f "$input_file" ]]; then
        echo "N/A"
        return
    fi
    
    case "$parameter" in
        "controller_count")
            # Количество контроллеров из "Number of Controllers = X"
            grep "Number of Controllers" "$input_file" 2>/dev/null | sed -n 's/.*= *\([0-9]\+\).*/\1/p' | head -1 || echo "0"
            ;;
        "controller_model")
            # Модель контроллера из "Product Name = "
            grep "^Product Name" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "N/A"
            ;;
        "controller_serial")
            # Серийный номер из "Serial Number = "
            grep "^Serial Number" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "N/A"
            ;;
        "sas_address")
            # SAS Address из "SAS Address = "
            grep "^SAS Address" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "N/A"
            ;;
        "pci_address")
            # PCI Address из "PCI Address = "
            grep "^PCI Address" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "N/A"
            ;;
        "firmware_version")
            # Версия прошивки из "FW Version = "
            grep "^FW Version" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "N/A"
            ;;
        "fw_package_build")
            # FW Package Build из "FW Package Build = "
            grep "^FW Package Build" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "N/A"
            ;;
        "bios_version")
            # Версия BIOS из "BIOS Version = "
            grep "^BIOS Version" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "N/A"
            ;;
        "driver_name")
            # Имя драйвера из "Driver Name = "
            grep "^Driver Name" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "N/A"
            ;;
        "driver_version")
            # Версия драйвера из "Driver Version = "
            grep "^Driver Version" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "N/A"
            ;;
        "personality")
            # Current Personality из "Current Personality = "
            grep "^Current Personality" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "N/A"
            ;;
        "host_interface")
            # Host Interface из "Host Interface = "
            grep "^Host Interface" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "N/A"
            ;;
        "drive_groups")
            # Количество групп дисков из "Drive Groups = "
            grep "^Drive Groups" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "0"
            ;;
        "virtual_drives")
            # Количество виртуальных дисков из "Virtual Drives = "
            grep "^Virtual Drives" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "0"
            ;;
        "physical_drives")
            # Количество физических дисков из "Physical Drives = "
            grep "^Physical Drives" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "0"
            ;;
        "enclosures")
            # Количество корпусов из "Enclosures = "
            grep "^Enclosures" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "0"
            ;;
        "system_time")
            # Системное время из "System Time = "
            grep "^System Time" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "N/A"
            ;;
        "controller_time")
            # Время контроллера из "Controller Time = "
            grep "^Controller Time" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "N/A"
            ;;
        "mfg_date")
            # Дата производства из "Mfg. Date = "
            grep "^Mfg\. Date" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "N/A"
            ;;
        "security_protocol")
            # Протокол безопасности из "Security Protocol = "
            grep "^Security Protocol" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs || echo "N/A"
            ;;
        "cachevault_model")
            # Модель CacheVault из секции Cachevault_Info
            awk '/^Cachevault_Info/,/^$/ {
                if ($0 ~ /^[A-Z0-9]+[ ]+[A-Za-z]+[ ]+[0-9]+C/) {
                    print $1; exit
                }
            }' "$input_file" 2>/dev/null || echo "N/A"
            ;;
        "cachevault_state")
            # Состояние CacheVault из секции Cachevault_Info
            awk '/^Cachevault_Info/,/^$/ {
                if ($0 ~ /^[A-Z0-9]+[ ]+[A-Za-z]+[ ]+[0-9]+C/) {
                    print $2; exit
                }
            }' "$input_file" 2>/dev/null || echo "N/A"
            ;;
        "cachevault_temp")
            # Температура CacheVault из секции Cachevault_Info
            awk '/^Cachevault_Info/,/^$/ {
                if ($0 ~ /^[A-Z0-9]+[ ]+[A-Za-z]+[ ]+[0-9]+C/) {
                    print $3; exit
                }
            }' "$input_file" 2>/dev/null || echo "N/A"
            ;;
        "cachevault_mode")
            # Режим CacheVault из секции Cachevault_Info
            awk '/^Cachevault_Info/,/^$/ {
                if ($0 ~ /^[A-Z0-9]+[ ]+[A-Za-z]+[ ]+[0-9]+C/) {
                    print $4; exit
                }
            }' "$input_file" 2>/dev/null || echo "N/A"
            ;;
        "cachevault_mfg_date")
            # Дата производства CacheVault из секции Cachevault_Info
            awk '/^Cachevault_Info/,/^$/ {
                if ($0 ~ /^[A-Z0-9]+[ ]+[A-Za-z]+[ ]+[0-9]+C/) {
                    print $5; exit
                }
            }' "$input_file" 2>/dev/null || echo "N/A"
            ;;
        "raid_levels")
            # RAID уровни из секции VD LIST
            awk '/^VD LIST/,/^$/ {
                if ($0 ~ /^[0-9]+\/[0-9]+/) {
                    print $2
                }
            }' "$input_file" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//' || echo "N/A"
            ;;
        "vd_info")
            # Информация о виртуальных дисках из секции VD LIST
            awk '/^VD LIST/,/^$/ {
                if ($0 ~ /^[0-9]+\/[0-9]+/) {
                    # Парсим строку вида: 0/0   RAID1  Optl  RW     Yes     RWBD  -   ON  893.137 GB RAID1_OS
                    vd_id = $1
                    raid_type = $2
                    size = $(NF-1) " " $NF
                    name = ""
                    # Проверяем наличие имени (последнее поле если не размер)
                    if (NF > 9 && $(NF-2) != "GB" && $(NF-2) != "TB") {
                        name = $(NF-2)
                    }
                    if (name == "") name = "Unnamed"
                    print vd_id ":" raid_type ":" size ":" name
                }
            }' "$input_file" 2>/dev/null | tr '\n' '; ' | sed 's/; $//' || echo "N/A"
            ;;
        "pd_count_by_type")
            # Количество физических дисков по типу из секции PD LIST
            local ssd_count=$(awk '/^PD LIST/,/^$/ {
                if ($0 ~ /^[0-9]+:[0-9]+/ && $0 ~ /SSD/) count++
            } END {print count+0}' "$input_file" 2>/dev/null)
            local hdd_count=$(awk '/^PD LIST/,/^$/ {
                if ($0 ~ /^[0-9]+:[0-9]+/ && $0 ~ /HDD/) count++
            } END {print count+0}' "$input_file" 2>/dev/null)
            echo "SSD:$ssd_count;HDD:$hdd_count"
            ;;
        "system_overview")
            # Системный обзор из секции System Overview
            awk '/^System Overview/,/^\s*$/ {
                if ($0 ~ /^[ ]*[0-9]/ && NF >= 10) {
                    print "Ctl:" $2 ";Ports:" $3 ";PDs:" $4 ";DGs:" $5 ";VDs:" $7 ";BBU:" $9 ";Health:" $NF
                    exit
                }
            }' "$input_file" 2>/dev/null || echo "N/A"
            ;;
        "topology_summary")
            # Краткая сводка топологии из секции TOPOLOGY
            local raid1_count=$(awk '/^TOPOLOGY/,/^$/ {
                if ($0 ~ /RAID1/) count++
            } END {print count+0}' "$input_file" 2>/dev/null)
            local raid10_count=$(awk '/^TOPOLOGY/,/^$/ {
                if ($0 ~ /RAID10/) count++
            } END {print count+0}' "$input_file" 2>/dev/null)
            local raid0_count=$(awk '/^TOPOLOGY/,/^$/ {
                if ($0 ~ /RAID0/) count++
            } END {print count+0}' "$input_file" 2>/dev/null)
            local raid5_count=$(awk '/^TOPOLOGY/,/^$/ {
                if ($0 ~ /RAID5/) count++
            } END {print count+0}' "$input_file" 2>/dev/null)
            local raid6_count=$(awk '/^TOPOLOGY/,/^$/ {
                if ($0 ~ /RAID6/) count++
            } END {print count+0}' "$input_file" 2>/dev/null)
            echo "RAID0:$raid0_count;RAID1:$raid1_count;RAID5:$raid5_count;RAID6:$raid6_count;RAID10:$raid10_count"
            ;;
        "degraded_drives")
            # Деградированные диски из секции TOPOLOGY (ищем статусы отличные от Optl/Optn/Onln)
            awk '/^TOPOLOGY/,/^$/ {
                if ($0 ~ /^[ ]*[0-9]/ && $6 !~ /Optl|Optn|Onln/ && $6 ~ /Dgrd|Offln|Failed|Rbld/) {
                    count++
                }
            } END {print count+0}' "$input_file" 2>/dev/null || echo "0"
            ;;
        "enclosure_info")
            # Информация о корпусах из секции Enclosure LIST
            awk '/^Enclosure LIST/,/^$/ {
                if ($0 ~ /^[ ]*[0-9]+/ && NF >= 10) {
                    print $1 ":" $2 ":" $3 "PD"
                }
            }' "$input_file" 2>/dev/null | tr '\n' '; ' | sed 's/; $//' || echo "N/A"
            ;;
        "detailed_pd_info")
            # Детальная информация о физических дисках
            awk '/^PD LIST/,/^$/ {
                if ($0 ~ /^[0-9]+:[0-9]+/) {
                    # Формат: EID:Slt DID State DG Size Intf Med SED PI SeSz Model Sp Type
                    eid_slot = $1
                    state = $3
                    size = $5 " " $6
                    interface = $7
                    media = $8
                    model = $NF-2
                    print eid_slot ":" state ":" size ":" interface ":" media ":" model
                }
            }' "$input_file" 2>/dev/null | tr '\n' '; ' | sed 's/; $//' || echo "N/A"
            ;;
        "detailed_vd_info")
            # Детальная информация о виртуальных дисках
            awk '/^VD LIST/,/^$/ {
                if ($0 ~ /^[0-9]+\/[0-9]+/) {
                    # Формат: DG/VD TYPE State Access Consist Cache Cac sCC Size Name
                    dg_vd = $1
                    type = $2
                    state = $3
                    access = $4
                    consist = $5
                    cache = $6
                    size = $(NF-1) " " $NF
                    name = ""
                    if (NF > 9 && $(NF-2) != "GB" && $(NF-2) != "TB") {
                        name = $(NF-2)
                    }
                    if (name == "") name = "Unnamed"
                    print dg_vd ":" type ":" state ":" access ":" cache ":" size ":" name
                }
            }' "$input_file" 2>/dev/null | tr '\n' '; ' | sed 's/; $//' || echo "N/A"
            ;;
        "vendor_device_info")
            # Информация о поставщике и устройстве
            local vendor_id=$(grep "^Vendor Id" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs)
            local device_id=$(grep "^Device Id" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs)
            local subvendor_id=$(grep "^SubVendor Id" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs)
            local subdevice_id=$(grep "^SubDevice Id" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs)
            echo "VendorId:${vendor_id:-N/A};DeviceId:${device_id:-N/A};SubVendorId:${subvendor_id:-N/A};SubDeviceId:${subdevice_id:-N/A}"
            ;;
        "bus_info")
            # Информация о шине
            local bus_number=$(grep "^Bus Number" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs)
            local device_number=$(grep "^Device Number" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs)
            local function_number=$(grep "^Function Number" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs)
            local domain_id=$(grep "^Domain ID" "$input_file" 2>/dev/null | sed 's/.*= *//' | xargs)
            echo "Bus:${bus_number:-N/A};Device:${device_number:-N/A};Function:${function_number:-N/A};Domain:${domain_id:-N/A}"
            ;;
        "lspci_controller_info")
            # Информация о контроллере из lspci
            grep "RAID bus controller\|MegaRAID" "$input_file" 2>/dev/null | head -1 | sed 's/^[^:]*: *//' || echo "N/A"
            ;;
        *)
            echo "N/A"
            ;;
    esac
}

# Основная функция запуска генерации отчета
main() {
    echo -e "${BLUE}=== Генерация детализированного отчета по RAID контроллерам ===${NC}"
    echo -e "${BLUE}Директория аудита: $AUDIT_DIR${NC}"
    echo ""
    
    # Проверяем наличие директории аудита
    if [[ ! -d "$AUDIT_DIR" ]]; then
        echo -e "${RED}Ошибка: Директория аудита '$AUDIT_DIR' не найдена!${NC}"
        echo -e "${YELLOW}Использование: $0 [путь_к_директории_аудита]${NC}"
        exit 1
    fi
    
    # Генерируем детализированную таблицу
    create_detailed_raid_info_table > "raid_detailed_report_$(date +%Y%m%d_%H%M%S).csv"
    
    echo -e "${GREEN}Детализированный отчет сохранен в файл: raid_detailed_report_$(date +%Y%m%d_%H%M%S).csv${NC}"
    
    # Выводим краткую статистику
    echo -e "\n${BLUE}=== Краткая статистика по серверам ===${NC}"
    local server_ips=($(get_server_ips))
    
    for server_ip in "${server_ips[@]}"; do
        echo -e "\n${YELLOW}Сервер: $server_ip${NC}"
        local controller_count=$(parse_raid_parameter "$server_ip" "controller_count")
        local controller_model=$(parse_raid_parameter "$server_ip" "controller_model")
        local physical_drives=$(parse_raid_parameter "$server_ip" "physical_drives")
        local virtual_drives=$(parse_raid_parameter "$server_ip" "virtual_drives")
        local raid_levels=$(parse_raid_parameter "$server_ip" "raid_levels")
        local degraded_drives=$(parse_raid_parameter "$server_ip" "degraded_drives")
        
        echo "  Контроллеры: $controller_count"
        echo "  Модель: $controller_model"
        echo "  Физические диски: $physical_drives"
        echo "  Виртуальные диски: $virtual_drives"
        echo "  RAID уровни: $raid_levels"
        
        if [[ "$degraded_drives" != "0" && "$degraded_drives" != "N/A" ]]; then
            echo -e "  ${RED}Деградированные диски: $degraded_drives${NC}"
        else
            echo -e "  ${GREEN}Деградированные диски: $degraded_drives${NC}"
        fi
    done
}

# Запускаем основную функцию если скрипт вызван напрямую
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
