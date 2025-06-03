#!/bin/bash

# Список серверов для аудита (скопирован из audit2.sh)
SERVERS=(
    "192.168.72.4:service"
    "192.168.72.5:service"
    "192.168.72.6:service"
    "192.168.72.7:service"
)

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
    
    ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$user@$server_ip" "$command" 2>/dev/null || true
}

# Функция для проверки наличия RAID контроллеров
check_raid_controllers() {
    local server_info="$1"
    local server_ip=$(echo "$server_info" | cut -d: -f1)
    
    printf "[INFO] Проверка RAID контроллеров на %s...\n" "$server_ip"
    
    # Проверяем наличие LSI/Broadcom контроллеров через lspci
    local lspci_output
    lspci_output=$(execute_remote_command "$server_info" "lspci | grep -i 'lsi\|broadcom\|megaraid\|sas'") || true
    
    if [[ -n "$lspci_output" ]]; then
        printf "[FOUND] RAID контроллеры найдены на %s:\n" "$server_ip"
        printf "%s\n" "$lspci_output"
        return 0
    else
        printf "[NOT FOUND] RAID контроллеры не найдены на %s\n" "$server_ip"
        return 1
    fi
}

# Функция для проверки наличия утилит управления RAID
check_raid_utilities() {
    local server_info="$1"
    local server_ip=$(echo "$server_info" | cut -d: -f1)
    
    printf "[INFO] Проверка утилит управления RAID на %s...\n" "$server_ip"
    
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
    
    printf "[INFO] Установка StorCLI на %s...\n" "$server_ip"
    
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
    
    printf "[INFO] Установка MegaCLI на %s...\n" "$server_ip"
    
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
        echo "=== StorCLI Information ===" >> "$output_file"
        echo "StorCLI Path: $storcli_path" >> "$output_file"
        echo "" >> "$output_file"
        
        # Версия StorCLI
        echo "--- StorCLI Version ---" >> "$output_file"
        execute_remote_command "$server_info" "$storcli_path show version" >> "$output_file" || true
        echo "" >> "$output_file"
        
        # Информация о контроллерах
        echo "--- Controllers Information ---" >> "$output_file"
        execute_remote_command "$server_info" "$storcli_path show" >> "$output_file" || true
        echo "" >> "$output_file"
        
        # Детальная информация о контроллере 0 (если есть)
        echo "--- Controller 0 Details ---" >> "$output_file"
        execute_remote_command "$server_info" "$storcli_path /c0 show" >> "$output_file" || true
        echo "" >> "$output_file"
        
        # Физические диски
        echo "--- Physical Drives ---" >> "$output_file"
        execute_remote_command "$server_info" "$storcli_path /c0/eall/sall show" >> "$output_file" || true
        echo "" >> "$output_file"
        
        # Виртуальные диски
        echo "--- Virtual Drives ---" >> "$output_file"
        execute_remote_command "$server_info" "$storcli_path /c0/vall show" >> "$output_file" || true
        echo "" >> "$output_file"
        
    # Если есть MegaCLI
    elif [[ -n "$megacli_path" ]]; then
        echo "=== MegaCLI Information ===" >> "$output_file"
        echo "MegaCLI Path: $megacli_path" >> "$output_file"
        echo "" >> "$output_file"
        
        # Информация о контроллерах
        echo "--- Controllers Information ---" >> "$output_file"
        execute_remote_command "$server_info" "$megacli_path -AdpAllInfo -aALL" >> "$output_file" || true
        echo "" >> "$output_file"
        
        # Физические диски
        echo "--- Physical Drives ---" >> "$output_file"
        execute_remote_command "$server_info" "$megacli_path -PDList -aALL" >> "$output_file" || true
        echo "" >> "$output_file"
        
        # Логические диски
        echo "--- Logical Drives ---" >> "$output_file"
        execute_remote_command "$server_info" "$megacli_path -LDInfo -Lall -aALL" >> "$output_file" || true
        echo "" >> "$output_file"
        
    else
        echo "No RAID management utilities found" >> "$output_file"
    fi
    
    echo -e "${GREEN}[DONE]${NC} Информация о RAID сохранена в $output_file"
}

# Функция для парсинга данных RAID с сервера
parse_raid_data() {
    local server_ip="$1"
    local input_file="$AUDIT_DIR/$server_ip/02_raid_info.txt"
    
    # Массив для хранения данных сервера
    declare -A raid_data
    
    if [[ -f "$input_file" ]]; then
        # Ищем информацию о контроллерах
        local controllers=$(grep -i "megaraid\|lsi\|broadcom" "$input_file" | head -1)
        raid_data["controllers"]="${controllers:-N/A}"
        
        # Ищем количество физических дисков
        local pd_count=$(grep -c "Device Id:" "$input_file" 2>/dev/null || echo "0")
        raid_data["physical_drives"]="$pd_count"
        
        # Ищем количество виртуальных дисков
        local vd_count=$(grep -c "Virtual Drive:" "$input_file" 2>/dev/null || echo "0")
        raid_data["virtual_drives"]="$vd_count"
        
        # Определяем используемую утилиту
        if grep -q "StorCLI" "$input_file"; then
            raid_data["utility"]="StorCLI"
        elif grep -q "MegaCLI" "$input_file"; then
            raid_data["utility"]="MegaCLI"
        else
            raid_data["utility"]="None"
        fi
        
    else
        raid_data["controllers"]="N/A"
        raid_data["physical_drives"]="N/A"
        raid_data["virtual_drives"]="N/A"
        raid_data["utility"]="N/A"
    fi
    
    echo "${raid_data[controllers]}|${raid_data[physical_drives]}|${raid_data[virtual_drives]}|${raid_data[utility]}"
}

# Функция для создания строки таблицы
create_raid_table_row() {
    local row_type="$1"
    local command="$2"
    local category="$3"
    local parameter="$4"
    local server_ips=($(get_server_ips))
    
    local row="RAID контроллеры;02_raid_info.txt;$command;$category;$parameter"
    
    # Собираем данные со всех серверов
    for server_ip in "${server_ips[@]}"; do
        local raid_data=$(parse_raid_data "$server_ip")
        IFS='|' read -r controllers physical_drives virtual_drives utility <<< "$raid_data"
        
        case $row_type in
            "controllers")
                row="$row;$controllers"
                ;;
            "physical_drives")
                row="$row;$physical_drives"
                ;;
            "virtual_drives")
                row="$row;$virtual_drives"
                ;;
            "utility")
                row="$row;$utility"
                ;;
        esac
    done
    
    echo "$row"
}

# Функция для создания таблицы с информацией о RAID
create_raid_info_table() {
    # Выводим заголовок
    create_header
    
    # Выводим строки таблицы
    create_raid_table_row "controllers" "lspci" "Аппаратная конфигурация" "RAID контроллеры"
    create_raid_table_row "utility" "which storcli64/MegaCli64" "Программное обеспечение" "Утилита управления"
    create_raid_table_row "physical_drives" "storcli64/MegaCli64" "Конфигурация RAID" "Физические диски"
    create_raid_table_row "virtual_drives" "storcli64/MegaCli64" "Конфигурация RAID" "Виртуальные диски"
}

# Основная функция аудита RAID
audit_raid_controllers() {
    local install_missing="$1"
    
    printf "=== Аудит RAID контроллеров ===\n"
    printf "\n"
    
    # Создаем директорию аудита
    mkdir -p "$AUDIT_DIR"
    
    for server_info in "${SERVERS[@]}"; do
        local server_ip=$(echo "$server_info" | cut -d: -f1)
        printf "[SERVER] Обработка сервера %s\n" "$server_ip"
        printf "----------------------------------------\n"
        
        # Проверяем наличие RAID контроллеров
        if check_raid_controllers "$server_info"; then
            # Проверяем утилиты управления
            local utilities
            utilities=$(check_raid_utilities "$server_info") || true
            local storcli_path=$(echo "$utilities" | cut -d'|' -f1)
            local megacli_path=$(echo "$utilities" | cut -d'|' -f2)
            
            if [[ -n "$storcli_path" ]]; then
                printf "[FOUND] StorCLI найден: %s\n" "$storcli_path"
            elif [[ -n "$megacli_path" ]]; then
                printf "[FOUND] MegaCLI найден: %s\n" "$megacli_path"
            else
                printf "[NOT FOUND] Утилиты управления RAID не найдены\n"
                
                if [[ "$install_missing" == "true" ]]; then
                    printf "[ACTION] Попытка установки StorCLI...\n"
                    install_storcli "$server_info"
                    # Повторная проверка после установки
                    utilities=$(check_raid_utilities "$server_info") || true
                    storcli_path=$(echo "$utilities" | cut -d'|' -f1)
                fi
            fi
            
            # Собираем информацию о RAID
            collect_raid_info "$server_info" "$storcli_path" "$megacli_path"
        fi
        
        printf "\n"
    done
}

# Основная функция
main() {
    local install_missing="false"
    
    # Обработка аргументов
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                echo "Использование: $0 [опции] [директория_аудита]"
                echo ""
                echo "Опции:"
                echo "  --install    Автоматически устанавливать отсутствующие утилиты"
                echo "  --table      Создать только таблицу из существующих данных"
                echo "  --help, -h   Показать эту справку"
                echo ""
                echo "Примеры:"
                echo "  $0                           # Аудит без установки"
                echo "  $0 --install                 # Аудит с установкой утилит"
                echo "  $0 --table                   # Только создание таблицы"
                echo "  $0 server_audit_20241201     # Использовать указанную директорию"
                exit 0
                ;;
            --install)
                install_missing="true"
                shift
                ;;
            --table)
                create_raid_info_table
                exit 0
                ;;
            *)
                AUDIT_DIR="$1"
                shift
                ;;
        esac
    done
    
    # Проверяем, нужно ли только создать таблицу
    if [[ "$install_missing" == "false" ]] && [[ -d "$AUDIT_DIR" ]]; then
        printf "[INFO] Директория аудита существует. Хотите:\n"
        printf "1) Провести новый аудит\n"
        printf "2) Создать таблицу из существующих данных\n"
        read -p "Выберите действие (1/2): " choice
        
        if [[ "$choice" == "2" ]]; then
            create_raid_info_table
            exit 0
        fi
    fi
    
    # Проводим аудит
    audit_raid_controllers "$install_missing"
    
    printf "=== Аудит завершен ===\n"
    printf "Результаты сохранены в: %s\n" "$AUDIT_DIR"
    printf "\n"
    printf "Для создания таблицы выполните:\n"
    printf "%s --table %s\n" "$0" "$AUDIT_DIR"
}

# Запускаем основную функцию
main "$@"
